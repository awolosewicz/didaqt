/*
 * overhead_rx.c — Receiver CPU/memory overhead benchmark
 *
 * Receives raw Ethernet frames and optionally processes them through
 * the DiDAQt heartbeat scheduler.  Reports CPU time and peak RSS.
 *
 * Usage:
 *   sudo ./overhead_rx <interface> <num_senders> <ctrl_ip> <ctrl_port> <mode>
 *
 *   mode: "didaqt" — full heartbeat scheduling
 *         "baseline" — same receive loop, no DiDAQt calls
 *
 * Output (stdout, one CSV line):
 *   num_senders,mode,cpu_user_us,cpu_sys_us,peak_rss_kb,frames_received
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
#include <sys/resource.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include "didaqt.h"

#define FRAME_MAX      1600
#define ETH_HDR_LEN    14
#define VLAN_HDR_LEN   4
#define IP_HDR_LEN     20
#define UDP_HDR_LEN    8

#define SENDER_MAGIC   0xD1DA0754CAFE00AAULL

#define WARMUP_SEC     2
#define MEASURE_SEC    10

static volatile int running = 1;

static void handle_signal(__attribute__((unused)) int sig) { running = 0; }

static int l2_hdr_len(const uint8_t *frame)
{
    uint16_t etype;
    memcpy(&etype, frame + 12, 2);
    return (etype == htons(0x8100)) ? ETH_HDR_LEN + VLAN_HDR_LEN
                                    : ETH_HDR_LEN;
}

static long tv_to_us(struct timeval *tv)
{
    return tv->tv_sec * 1000000L + tv->tv_usec;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr,
                "Usage: %s <interface> <num_senders> <ctrl_ip> "
                "<ctrl_port> <mode>\n", argv[0]);
        return 1;
    }

    const char *ifname    = argv[1];
    int num_senders       = atoi(argv[2]);
    const char *ctrl_ip   = argv[3];
    uint16_t ctrl_port    = (uint16_t)atoi(argv[4]);
    const char *mode      = argv[5];

    int use_didaqt = (strcmp(mode, "didaqt") == 0);

    /* --- DiDAQt init (only in didaqt mode) --- */
    didaqt_rx_ctx *ctx = NULL;
    if (use_didaqt) {
        if (didaqt_rx_init_ctx(1, &ctx) != DIDAQT_OK) {
            fprintf(stderr, "didaqt_rx_init_ctx failed\n");
            return 1;
        }
        didaqt_rx_set_controller(ctx, ctrl_ip, ctrl_port);
        didaqt_rx_set_interval(ctx, 100);
        if (didaqt_rx_start(ctx) != DIDAQT_OK) {
            fprintf(stderr, "didaqt_rx_start failed\n");
            return 1;
        }
    }

    /* --- Open raw socket --- */
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) { perror("socket"); return 1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX"); close(sockfd); return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); close(sockfd); return 1;
    }

    /* Non-blocking receive with a timeout so we can check the clock. */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100ms */
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    /* --- Warmup phase --- */
    struct timespec ts_start, ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    uint8_t frame[FRAME_MAX];

    while (running) {
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        long elapsed = ts_now.tv_sec - ts_start.tv_sec;
        if (elapsed >= WARMUP_SEC) break;

        ssize_t n = recv(sockfd, frame, sizeof(frame), 0);
        if (n < 0) continue;

        if (n < ETH_HDR_LEN) continue;
        int l2len = l2_hdr_len(frame);
        if (n < l2len + IP_HDR_LEN + UDP_HDR_LEN + 8) continue;

        uint16_t inner_etype;
        memcpy(&inner_etype, frame + l2len - 2, 2);
        if (inner_etype != htons(0x0800)) continue;
        if (frame[l2len + 9] != 17) continue;

        if (use_didaqt) {
            uint32_t s_id = (uint32_t)frame[l2len + 14];

            int magic_off = l2len + IP_HDR_LEN + UDP_HDR_LEN;
            uint64_t magic;
            memcpy(&magic, frame + magic_off, sizeof(magic));
            magic = be64toh(magic);

            if (magic == SENDER_MAGIC)
                schedule_heartbeat(s_id, ctx);
        }
    }

    /* --- Measurement phase --- */
    struct rusage ru_before, ru_after;
    getrusage(RUSAGE_SELF, &ru_before);
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    uint64_t frames_received = 0;

    while (running) {
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        long elapsed = ts_now.tv_sec - ts_start.tv_sec;
        if (elapsed >= MEASURE_SEC) break;

        ssize_t n = recv(sockfd, frame, sizeof(frame), 0);
        if (n < 0) continue;

        if (n < ETH_HDR_LEN) continue;
        int l2len = l2_hdr_len(frame);
        if (n < l2len + IP_HDR_LEN + UDP_HDR_LEN + 8) continue;

        uint16_t inner_etype;
        memcpy(&inner_etype, frame + l2len - 2, 2);
        if (inner_etype != htons(0x0800)) continue;
        if (frame[l2len + 9] != 17) continue;

        frames_received++;

        uint32_t s_id = (uint32_t)frame[l2len + 14];

        int magic_off = l2len + IP_HDR_LEN + UDP_HDR_LEN;
        uint64_t magic;
        memcpy(&magic, frame + magic_off, sizeof(magic));
        magic = be64toh(magic);

        if (use_didaqt && magic == SENDER_MAGIC)
            schedule_heartbeat(s_id, ctx);
    }

    getrusage(RUSAGE_SELF, &ru_after);

    long cpu_user_us = tv_to_us(&ru_after.ru_utime)
                     - tv_to_us(&ru_before.ru_utime);
    long cpu_sys_us  = tv_to_us(&ru_after.ru_stime)
                     - tv_to_us(&ru_before.ru_stime);
    long peak_rss_kb = ru_after.ru_maxrss;

    printf("%d,%s,%ld,%ld,%ld,%lu\n",
           num_senders, mode, cpu_user_us, cpu_sys_us,
           peak_rss_kb, (unsigned long)frames_received);

    close(sockfd);
    if (use_didaqt)
        didaqt_rx_stop(ctx);

    return 0;
}
