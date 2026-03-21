/*
 * receiver.c — Example DAQ data receiver with DiDAQt heartbeats
 *
 * Receives Ethernet/IPv4/UDP frames on a raw socket, validates the
 * 8-byte magic value at the start of the UDP payload, and calls
 * schedule_heartbeat() for every sender whose data passes validation.
 *
 * The DiDAQt receiver context runs a background thread that
 * periodically sends heartbeat packets to the controller.
 *
 * Usage:
 *   ./receiver <interface> <receiver_id> <controller_ip> <controller_port>
 *
 * Example:
 *   ./receiver eth1 1 192.168.1.100 9000
 *
 * Build:
 *   gcc -O2 -Wall -pthread -Iinclude -o receiver \
 *       examples/receiver.c src/didaqt_rx.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include "didaqt.h"

/* --------------------------------------------------------------- */
/*  Constants                                                       */
/* --------------------------------------------------------------- */

#define FRAME_MAX      1600
#define ETH_HDR_LEN    14
#define IP_HDR_LEN     20
#define UDP_HDR_LEN    8
#define MAGIC_OFFSET   (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)

/* Must match the sender's magic value. */
#define SENDER_MAGIC   0xD1DA0754CAFE00AAULL

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* --------------------------------------------------------------- */
/*  Extract a sender ID from a received frame                       */
/* --------------------------------------------------------------- */

/*
 * Derive a sender ID from the source IP address in the IPv4 header.
 * The sender encodes its ID as the third octet of 10.0.<id>.1, so
 * we just pull that byte.
 */
static uint32_t sender_id_from_frame(const uint8_t *frame)
{
    const uint8_t *ip = frame + ETH_HDR_LEN;
    /* Source IP is at offset 12 within the IPv4 header. */
    return (uint32_t)ip[14];   /* third octet of src IP */
}

/* --------------------------------------------------------------- */
/*  Main                                                            */
/* --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr,
                "Usage: %s <interface> <receiver_id> "
                "<controller_ip> <controller_port>\n", argv[0]);
        return 1;
    }

    const char *ifname    = argv[1];
    uint32_t receiver_id  = (uint32_t)atoi(argv[2]);
    const char *ctrl_ip   = argv[3];
    uint16_t ctrl_port    = (uint16_t)atoi(argv[4]);

    /* --- Initialise DiDAQt receiver context --- */
    didaqt_rx_ctx *ctx = NULL;
    if (didaqt_rx_init_ctx(receiver_id, &ctx) != DIDAQT_OK) {
        fprintf(stderr, "didaqt_rx_init_ctx failed\n");
        return 1;
    }
    if (didaqt_rx_set_controller(ctx, ctrl_ip, ctrl_port) != DIDAQT_OK) {
        fprintf(stderr, "didaqt_rx_set_controller failed\n");
        return 1;
    }
    if (didaqt_rx_start(ctx) != DIDAQT_OK) {
        fprintf(stderr, "didaqt_rx_start failed\n");
        return 1;
    }

    /* --- Open raw receive socket --- */
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0) {
        perror("socket");
        didaqt_rx_stop(ctx);
        return 1;
    }

    /* Bind to the specified interface. */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        didaqt_rx_stop(ctx);
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_IP);

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        didaqt_rx_stop(ctx);
        return 1;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("receiver %u: listening on %s, heartbeats -> %s:%u\n",
           receiver_id, ifname, ctrl_ip, ctrl_port);

    /* --- Receive loop --- */
    uint8_t  frame[FRAME_MAX];
    uint64_t rx_count = 0;
    uint64_t rx_valid = 0;

    while (running) {
        ssize_t n = recv(sockfd, frame, sizeof(frame), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }

        /* Need at least headers + 8-byte magic. */
        if (n < MAGIC_OFFSET + 8)
            continue;

        /* Verify IP protocol is UDP. */
        uint8_t proto = frame[ETH_HDR_LEN + 9];
        if (proto != 17)
            continue;

        rx_count++;

        /* Validate the 8-byte magic at the start of the UDP payload. */
        uint64_t magic;
        memcpy(&magic, frame + MAGIC_OFFSET, sizeof(magic));
        magic = be64toh(magic);

        if (magic == SENDER_MAGIC) {
            uint32_t s_id = sender_id_from_frame(frame);
            schedule_heartbeat(s_id, ctx);
            rx_valid++;
        }

        if ((rx_count & 0xFFFFF) == 0) {
            printf("receiver %u: %lu frames, %lu valid\n",
                   receiver_id, rx_count, rx_valid);
        }
    }

    close(sockfd);
    didaqt_rx_stop(ctx);
    printf("receiver %u: stopped (%lu frames, %lu valid)\n",
           receiver_id, rx_count, rx_valid);
    return 0;
}
