/*
 * overhead_ctrl.c — Controller CPU/memory overhead benchmark
 *
 * Loads a topology, primes the controller to steady state, then
 * receives UDP heartbeats and optionally processes them through
 * didaqt_ctrl_process_heartbeat().  Reports CPU time and peak RSS.
 *
 * Usage:
 *   ./overhead_ctrl <port> <topology_yaml> <num_receivers>
 *                   <senders_per_hb> <mode> [ready_file]
 *
 *   mode: "didaqt"   — full heartbeat processing
 *         "baseline" — receive packets, skip process_heartbeat
 *
 *   ready_file: if provided, this file is created after the controller
 *               has loaded the topology, primed senders, and bound the
 *               UDP socket — signaling that the heartbeat generator
 *               can begin sending.
 *
 * Output (stdout, one CSV line):
 *   num_receivers,senders_per_hb,mode,cpu_user_us,cpu_sys_us,
 *   peak_rss_kb,packets_received
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
#include <sys/socket.h>
#include <netinet/in.h>

#include "didaqt.h"

#define WARMUP_SEC     2
#define MEASURE_SEC    10
#define MAX_PKT_SIZE   4096

static volatile int running = 1;

static void handle_signal(__attribute__((unused)) int sig) { running = 0; }

static int mock_handler(__attribute__((unused)) uint64_t sid,
                        __attribute__((unused)) int ci,
                        __attribute__((unused)) int co,
                        __attribute__((unused)) int ni,
                        __attribute__((unused)) int no,
                        __attribute__((unused)) void *ud)
{
    return 0;
}

/* Build and feed one heartbeat for receiver rid with senders
 * first_sid through first_sid + count - 1. */
static void prime_heartbeat(didaqt_ctrl_ctx *ctx, uint32_t rid,
                            uint32_t first_sid, int count)
{
    size_t pkt_sz = 6 + (size_t)count * 4;
    uint8_t *buf = malloc(pkt_sz);
    if (!buf) return;

    uint32_t r = htonl(rid);
    uint16_t c = htons((uint16_t)count);
    memcpy(buf, &r, 4);
    memcpy(buf + 4, &c, 2);
    for (int i = 0; i < count; i++) {
        uint32_t s = htonl(first_sid + (uint32_t)i);
        memcpy(buf + 6 + i * 4, &s, 4);
    }

    didaqt_ctrl_process_heartbeat(buf, pkt_sz, ctx);
    free(buf);
}

static long tv_to_us(struct timeval *tv)
{
    return tv->tv_sec * 1000000L + tv->tv_usec;
}

int main(int argc, char **argv)
{
    if (argc < 6 || argc > 7) {
        fprintf(stderr,
                "Usage: %s <port> <topology_yaml> <num_receivers> "
                "<senders_per_hb> <mode> [ready_file]\n", argv[0]);
        return 1;
    }

    uint16_t port         = (uint16_t)atoi(argv[1]);
    const char *yaml_path = argv[2];
    int num_receivers     = atoi(argv[3]);
    int senders_per_hb    = atoi(argv[4]);
    const char *mode      = argv[5];
    const char *ready_file = (argc >= 7) ? argv[6] : NULL;

    int use_didaqt = (strcmp(mode, "didaqt") == 0);

    /* --- Controller init (didaqt mode only) --- */
    didaqt_ctrl_ctx *ctx = NULL;

    if (use_didaqt) {
        if (didaqt_ctrl_init_ctx(&ctx) != DIDAQT_OK) {
            fprintf(stderr, "init_ctx failed\n");
            return 1;
        }

        didaqt_ctrl_set_miss_threshold(ctx, 3);
        didaqt_ctrl_set_grace_period(ctx, 1000000000L);

        fprintf(stderr, "ctrl: loading topology...\n");
        if (didaqt_ctrl_process_topology(yaml_path, ctx) != DIDAQT_OK) {
            fprintf(stderr, "process_topology failed\n");
            didaqt_ctrl_destroy(ctx);
            return 1;
        }
        fprintf(stderr, "ctrl: topology loaded\n");

        if (didaqt_ctrl_register_handler(ctx, "tofino2",
                                          mock_handler, NULL) != DIDAQT_OK) {
            fprintf(stderr, "register_handler failed\n");
            didaqt_ctrl_destroy(ctx);
            return 1;
        }

        /* Prime: send two rounds of heartbeats so all senders are "seen". */
        for (int round = 0; round < 2; round++) {
            for (int r = 0; r < num_receivers; r++) {
                uint32_t rid = (uint32_t)(r + 1);
                uint32_t first_sid = (uint32_t)(r * senders_per_hb + 1);
                prime_heartbeat(ctx, rid, first_sid, senders_per_hb);
            }
        }
        fprintf(stderr, "ctrl: primed %d receivers\n", num_receivers);
    }

    /* --- Open UDP socket --- */
    int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    int opt = 0;
    setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(port);
    addr.sin6_addr   = in6addr_any;

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(sockfd); return 1;
    }

    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    fprintf(stderr, "ctrl: listening on port %u, mode=%s\n", port, mode);

    /* Signal readiness so the heartbeat generator can start. */
    if (ready_file) {
        FILE *rf = fopen(ready_file, "w");
        if (rf) { fprintf(rf, "ready\n"); fclose(rf); }
    }

    /* --- Warmup phase --- */
    struct timespec ts_start, ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    uint8_t pkt[MAX_PKT_SIZE];

    while (running) {
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        if (ts_now.tv_sec - ts_start.tv_sec >= WARMUP_SEC) break;

        ssize_t n = recv(sockfd, pkt, sizeof(pkt), 0);
        if (n < 0) continue;

        if (use_didaqt && n >= 6)
            didaqt_ctrl_process_heartbeat(pkt, (size_t)n, ctx);
    }

    /* --- Measurement phase --- */
    struct rusage ru_before, ru_after;
    getrusage(RUSAGE_SELF, &ru_before);
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    uint64_t packets_received = 0;

    while (running) {
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        if (ts_now.tv_sec - ts_start.tv_sec >= MEASURE_SEC) break;

        ssize_t n = recv(sockfd, pkt, sizeof(pkt), 0);
        if (n < 0) continue;
        if (n < 6) continue;

        packets_received++;

        if (use_didaqt)
            didaqt_ctrl_process_heartbeat(pkt, (size_t)n, ctx);
    }

    getrusage(RUSAGE_SELF, &ru_after);

    long cpu_user_us = tv_to_us(&ru_after.ru_utime)
                     - tv_to_us(&ru_before.ru_utime);
    long cpu_sys_us  = tv_to_us(&ru_after.ru_stime)
                     - tv_to_us(&ru_before.ru_stime);
    long peak_rss_kb = ru_after.ru_maxrss;

    printf("%d,%d,%s,%ld,%ld,%ld,%lu\n",
           num_receivers, senders_per_hb, mode,
           cpu_user_us, cpu_sys_us, peak_rss_kb,
           (unsigned long)packets_received);

    close(sockfd);
    if (use_didaqt)
        didaqt_ctrl_destroy(ctx);

    return 0;
}
