/*
 * overhead_hb_gen.c — Multi-receiver heartbeat generator
 *
 * Sends UDP heartbeat packets simulating N receivers, each reporting
 * S senders.  Heartbeats are sent every 100ms in a burst.
 *
 * Receiver r (1..N) lists sender IDs (r-1)*S+1 through r*S.
 * Wire format matches didaqt.h heartbeat specification.
 *
 * Usage:
 *   ./overhead_hb_gen <dest_ip> <dest_port> <num_receivers> <senders_per_hb>
 *
 * Runs until SIGTERM/SIGINT.
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
#include <sys/socket.h>
#include <netinet/in.h>

#define HB_INTERVAL_NS 100000000L  /* 100 ms */

static volatile int running = 1;

static void handle_signal(__attribute__((unused)) int sig) { running = 0; }

/*
 * Build a heartbeat packet for receiver rid with sender IDs
 * first_sid through first_sid + count - 1.
 * Returns packet length.
 */
static int build_hb(uint32_t rid, uint32_t first_sid, int count,
                    uint8_t *buf, size_t sz)
{
    size_t need = 6 + (size_t)count * 4;
    if (need > sz) return -1;

    uint32_t r = htonl(rid);
    uint16_t c = htons((uint16_t)count);
    memcpy(buf, &r, 4);
    memcpy(buf + 4, &c, 2);
    for (int i = 0; i < count; i++) {
        uint32_t s = htonl(first_sid + (uint32_t)i);
        memcpy(buf + 6 + i * 4, &s, 4);
    }
    return (int)need;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr,
                "Usage: %s <dest_ip> <dest_port> <num_receivers> "
                "<senders_per_hb>\n", argv[0]);
        return 1;
    }

    const char *dest_ip   = argv[1];
    uint16_t dest_port    = (uint16_t)atoi(argv[2]);
    int num_receivers     = atoi(argv[3]);
    int senders_per_hb    = atoi(argv[4]);

    if (num_receivers < 1 || senders_per_hb < 1) {
        fprintf(stderr, "num_receivers and senders_per_hb must be >= 1\n");
        return 1;
    }

    /* Resolve destination address. */
    struct sockaddr_in6 dst6;
    struct sockaddr_in  dst4;
    struct sockaddr *dst;
    socklen_t dst_len;
    int af;

    memset(&dst6, 0, sizeof(dst6));
    memset(&dst4, 0, sizeof(dst4));

    if (inet_pton(AF_INET6, dest_ip, &dst6.sin6_addr) == 1) {
        af = AF_INET6;
        dst6.sin6_family = AF_INET6;
        dst6.sin6_port   = htons(dest_port);
        dst = (struct sockaddr *)&dst6;
        dst_len = sizeof(dst6);
    } else if (inet_pton(AF_INET, dest_ip, &dst4.sin_addr) == 1) {
        af = AF_INET;
        dst4.sin_family = AF_INET;
        dst4.sin_port   = htons(dest_port);
        dst = (struct sockaddr *)&dst4;
        dst_len = sizeof(dst4);
    } else {
        fprintf(stderr, "Invalid IP address: %s\n", dest_ip);
        return 1;
    }

    int sockfd = socket(af, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    /* Pre-build heartbeat packets. */
    size_t pkt_size = 6 + (size_t)senders_per_hb * 4;
    uint8_t *packets = malloc((size_t)num_receivers * pkt_size);
    if (!packets) { perror("malloc"); close(sockfd); return 1; }

    for (int r = 0; r < num_receivers; r++) {
        uint32_t rid = (uint32_t)(r + 1);
        uint32_t first_sid = (uint32_t)(r * senders_per_hb + 1);
        build_hb(rid, first_sid, senders_per_hb,
                 packets + (size_t)r * pkt_size, pkt_size);
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    fprintf(stderr, "hb_gen: sending for %d receivers, %d senders/hb, "
            "pkt_size=%zu\n", num_receivers, senders_per_hb, pkt_size);

    uint64_t rounds = 0;
    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);

    while (running) {
        /* Send all heartbeats in a burst. */
        for (int r = 0; r < num_receivers && running; r++) {
            sendto(sockfd, packets + (size_t)r * pkt_size, pkt_size, 0,
                   dst, dst_len);
        }
        rounds++;

        /* Sleep until next interval. */
        next.tv_nsec += HB_INTERVAL_NS;
        if (next.tv_nsec >= 1000000000L) {
            next.tv_nsec -= 1000000000L;
            next.tv_sec++;
        }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
    }

    free(packets);
    close(sockfd);
    fprintf(stderr, "hb_gen: sent %lu rounds\n", (unsigned long)rounds);
    return 0;
}
