/*
 * receiver.c — Example DAQ data receiver with DiDAQt heartbeats
 *
 * Receives Ethernet frames on a raw socket, handling both plain and
 * 802.1Q VLAN-tagged frames.  Validates the 8-byte magic value at
 * the start of the UDP payload and calls schedule_heartbeat() for
 * every sender whose data passes validation.
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
#define VLAN_HDR_LEN   4
#define IP_HDR_LEN     20
#define UDP_HDR_LEN    8

/* Must match the sender's magic value. */
#define SENDER_MAGIC   0xD1DA0754CAFE00AAULL

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* --------------------------------------------------------------- */
/*  Frame helpers                                                   */
/* --------------------------------------------------------------- */

/*
 * Return the L2 header length for a frame: 14 for plain Ethernet,
 * 18 if an 802.1Q VLAN tag is present.
 */
static int l2_hdr_len(const uint8_t *frame)
{
    uint16_t etype;
    memcpy(&etype, frame + 12, 2);
    return (etype == htons(0x8100)) ? ETH_HDR_LEN + VLAN_HDR_LEN
                                    : ETH_HDR_LEN;
}

/*
 * Derive a sender ID from the source IP address in the IPv4 header.
 * The sender encodes its ID as the third octet of 10.0.<id>.1, so
 * we pull that byte.  l2len is the L2 header length (14 or 18).
 */
static uint32_t sender_id_from_frame(const uint8_t *frame, int l2len)
{
    const uint8_t *ip = frame + l2len;
    /* Source IP offset 12 within IP header; third octet at +14. */
    return (uint32_t)ip[14];
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

    /* --- Open raw receive socket ---
     * Use ETH_P_ALL to capture both plain and VLAN-tagged frames. */
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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
    sll.sll_protocol = htons(ETH_P_ALL);

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

        /* Determine L2 header length (handles VLAN or plain). */
        if (n < ETH_HDR_LEN)
            continue;
        int l2len = l2_hdr_len(frame);

        /* Minimum: L2 + IP + UDP + 8-byte magic. */
        if (n < l2len + IP_HDR_LEN + UDP_HDR_LEN + 8)
            continue;

        /* Check EtherType after any VLAN tag is IPv4 (0x0800). */
        uint16_t inner_etype;
        memcpy(&inner_etype, frame + l2len - 2, 2);
        if (inner_etype != htons(0x0800))
            continue;

        /* Verify IP protocol is UDP. */
        uint8_t proto = frame[l2len + 9];
        if (proto != 17)
            continue;

        rx_count++;

        /* Validate the 8-byte magic at the start of the UDP payload. */
        int magic_off = l2len + IP_HDR_LEN + UDP_HDR_LEN;
        uint64_t magic;
        memcpy(&magic, frame + magic_off, sizeof(magic));
        magic = be64toh(magic);

        uint32_t s_id = sender_id_from_frame(frame, l2len);
        if (magic == SENDER_MAGIC) {
            schedule_heartbeat(s_id, ctx);
            rx_valid++;
        } else {
            deschedule_heartbeat(s_id, ctx);
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
