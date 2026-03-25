/*
 * receiver.c — Example DAQ data receiver with DiDAQt heartbeats
 *
 * Receives Ethernet frames on a raw socket, handling both plain and
 * 802.1Q VLAN-tagged frames.  Validates the 8-byte magic value at
 * the start of the UDP payload and calls schedule_heartbeat() for
 * every sender whose data passes validation.
 *
 * Displays a live terminal UI showing per-sender frame counts.
 *
 * Usage:
 *   ./receiver <interface> <receiver_id> <controller_ip> <controller_port>
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
#include <time.h>

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

#define SENDER_MAGIC   0xD1DA0754CAFE00AAULL

#define MAX_TRACKED    256
#define DISPLAY_INTERVAL_NS 500000000L  /* 500 ms */

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* --------------------------------------------------------------- */
/*  Per-sender tracking                                             */
/* --------------------------------------------------------------- */

typedef struct {
    uint32_t s_id;
    uint64_t valid;
    uint64_t invalid;
} sender_stat;

static sender_stat tracked[MAX_TRACKED];
static int num_tracked = 0;

static sender_stat *get_sender(uint32_t s_id)
{
    for (int i = 0; i < num_tracked; i++)
        if (tracked[i].s_id == s_id)
            return &tracked[i];
    if (num_tracked < MAX_TRACKED) {
        sender_stat *s = &tracked[num_tracked++];
        memset(s, 0, sizeof(*s));
        s->s_id = s_id;
        return s;
    }
    return NULL;
}

/* --------------------------------------------------------------- */
/*  Terminal display                                                */
/* --------------------------------------------------------------- */

static void draw_display(uint32_t receiver_id, const char *ifname,
                         uint64_t rx_total)
{
    /* Move cursor to home position (no clear — reduces flicker). */
    printf("\033[H");

    printf("\033[1m  DiDAQt Receiver %u\033[0m — %s\033[K\n",
           receiver_id, ifname);
    printf("  Total frames: %lu\033[K\n", (unsigned long)rx_total);
    printf("  %-8s  %12s  %12s  %s\033[K\n",
           "Sender", "Valid", "Invalid", "Status");
    printf("  ──────────────────────────────────────────────\033[K\n");

    int healthy = 0, faulty = 0;
    for (int i = 0; i < num_tracked; i++) {
        sender_stat *s = &tracked[i];
        const char *status;
        const char *color;
        if (s->invalid == 0) {
            status = "OK";
            color  = "\033[32m";   /* green */
            healthy++;
        } else {
            status = "FAULT";
            color  = "\033[31m";   /* red */
            faulty++;
        }
        printf("  %-8u  %12lu  %12lu  %s%s\033[0m\033[K\n",
               s->s_id,
               (unsigned long)s->valid,
               (unsigned long)s->invalid,
               color, status);
    }

    printf("  ──────────────────────────────────────────────\033[K\n");
    printf("  %d sender(s): \033[32m%d OK\033[0m",
           num_tracked, healthy);
    if (faulty > 0)
        printf("  \033[31m%d FAULT\033[0m", faulty);
    printf("\033[K\n");

    /* Clear any leftover lines from a previously larger display. */
    printf("\033[J");
    fflush(stdout);
}

/* --------------------------------------------------------------- */
/*  Frame helpers                                                   */
/* --------------------------------------------------------------- */

static int l2_hdr_len(const uint8_t *frame)
{
    uint16_t etype;
    memcpy(&etype, frame + 12, 2);
    return (etype == htons(0x8100)) ? ETH_HDR_LEN + VLAN_HDR_LEN
                                    : ETH_HDR_LEN;
}

static uint32_t sender_id_from_frame(const uint8_t *frame, int l2len)
{
    const uint8_t *ip = frame + l2len;
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

    /* --- Open raw receive socket --- */
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        didaqt_rx_stop(ctx);
        return 1;
    }

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

    /* Clear screen and draw initial display. */
    printf("\033[2J");
    draw_display(receiver_id, ifname, 0);

    /* --- Receive loop --- */
    uint8_t  frame[FRAME_MAX];
    uint64_t rx_count = 0;
    struct timespec last_draw;
    clock_gettime(CLOCK_MONOTONIC, &last_draw);

    while (running) {
        ssize_t n = recv(sockfd, frame, sizeof(frame), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }

        if (n < ETH_HDR_LEN)
            continue;
        int l2len = l2_hdr_len(frame);

        if (n < l2len + IP_HDR_LEN + UDP_HDR_LEN + 8)
            continue;

        uint16_t inner_etype;
        memcpy(&inner_etype, frame + l2len - 2, 2);
        if (inner_etype != htons(0x0800))
            continue;

        uint8_t proto = frame[l2len + 9];
        if (proto != 17)
            continue;

        rx_count++;

        int magic_off = l2len + IP_HDR_LEN + UDP_HDR_LEN;
        uint64_t magic;
        memcpy(&magic, frame + magic_off, sizeof(magic));
        magic = be64toh(magic);

        uint32_t s_id = sender_id_from_frame(frame, l2len);
        sender_stat *ss = get_sender(s_id);

        if (magic == SENDER_MAGIC) {
            schedule_heartbeat(s_id, ctx);
            if (ss) ss->valid++;
        } else {
            deschedule_heartbeat(s_id, ctx);
            if (ss) ss->invalid++;
        }

        /* Refresh display periodically. */
        if ((rx_count & 0xFFFF) == 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed_ns = (now.tv_sec - last_draw.tv_sec) * 1000000000L
                            + (now.tv_nsec - last_draw.tv_nsec);
            if (elapsed_ns >= DISPLAY_INTERVAL_NS) {
                draw_display(receiver_id, ifname, rx_count);
                last_draw = now;
            }
        }
    }

    close(sockfd);
    didaqt_rx_stop(ctx);

    /* Final display. */
    draw_display(receiver_id, ifname, rx_count);
    printf("\n  Receiver %u stopped.\n", receiver_id);
    return 0;
}
