/*
 * controller.c — DiDAQt controller node
 *
 * Loads a network topology from a YAML file, performs static
 * reachability analysis, then listens for heartbeat packets and
 * runs the failover state machine.
 *
 * When a switch agent address is provided, failover actions are
 * sent as ICMPv6 echo request/reply messages to the agent running
 * on the Tofino, and the round-trip time is measured.  ICMPv6 is
 * used because FABRIC's management plane allows ICMP but blocks
 * arbitrary TCP/UDP between nodes.
 *
 * Usage:
 *   ./controller <topology.yaml> <heartbeat_port> [switch_ipv6]
 *
 * Examples:
 *   ./controller topology.yaml 9000                         # log-only
 *   ./controller topology.yaml 9000 2001:db8::1             # live updates
 *
 * Build:
 *   make build/controller
 *
 * Requires: CAP_NET_RAW (run with sudo).
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
#include <netinet/icmp6.h>
#include <netdb.h>

#include "didaqt.h"

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* ------------------------------------------------------------------ */
/*  ICMPv6 switch agent connection                                     */
/* ------------------------------------------------------------------ */

#define DIDAQT_ICMP_ID  0xDDAA

typedef struct {
    int                sockfd;    /* -1 = log-only mode */
    struct sockaddr_in6 dest;
    uint16_t           seq;
} switch_conn;

static int switch_conn_open(switch_conn *sc, const char *addr)
{
    memset(sc, 0, sizeof(*sc));
    sc->sockfd = -1;
    if (!addr) return 0;   /* log-only mode */

    /* Resolve IPv6 address. */
    if (inet_pton(AF_INET6, addr, &sc->dest.sin6_addr) != 1) {
        fprintf(stderr, "bad IPv6 address: %s\n", addr);
        return -1;
    }
    sc->dest.sin6_family = AF_INET6;

    /* Open raw ICMPv6 socket. */
    sc->sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sc->sockfd < 0) {
        perror("socket (ICMPv6 raw)");
        return -1;
    }

    /* Filter: only receive echo replies. */
    struct icmp6_filter filt;
    ICMP6_FILTER_SETBLOCKALL(&filt);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
    setsockopt(sc->sockfd, IPPROTO_ICMPV6, ICMP6_FILTER,
               &filt, sizeof(filt));

    /* Receive timeout for reliability. */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sc->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("ICMPv6 switch agent: %s\n", addr);
    return 0;
}

/*
 * Send a command via ICMPv6 echo request and wait for the agent's
 * echo reply.  The kernel on the switch will also auto-reply with
 * the original payload echoed back — we skip those and look for a
 * reply whose payload starts with "OK", "ERR", or "PONG".
 *
 * Returns the round-trip time in microseconds, or -1 on error.
 */
static long switch_conn_send(switch_conn *sc, const char *cmd,
                             char *resp_out, size_t resp_sz)
{
    if (sc->sockfd < 0) return 0;

    uint16_t seq = sc->seq++;
    size_t cmd_len = strlen(cmd);

    /* Build echo request: 8-byte header + payload. */
    size_t pkt_len = 8 + cmd_len;
    uint8_t pkt[8 + 256];
    if (pkt_len > sizeof(pkt)) pkt_len = sizeof(pkt);

    memset(pkt, 0, 8);
    pkt[0] = ICMP6_ECHO_REQUEST;           /* type   */
    pkt[1] = 0;                             /* code   */
    /* [2-3] checksum: kernel fills        */
    pkt[4] = (DIDAQT_ICMP_ID >> 8) & 0xFF; /* id hi  */
    pkt[5] = DIDAQT_ICMP_ID & 0xFF;        /* id lo  */
    pkt[6] = (seq >> 8) & 0xFF;             /* seq hi */
    pkt[7] = seq & 0xFF;                    /* seq lo */
    memcpy(pkt + 8, cmd, cmd_len);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (sendto(sc->sockfd, pkt, pkt_len, 0,
               (struct sockaddr *)&sc->dest, sizeof(sc->dest)) < 0) {
        perror("sendto ICMPv6");
        return -1;
    }

    /* Wait for agent reply (skip kernel auto-echoes). */
    uint8_t buf[8 + 256];
    for (int tries = 0; tries < 10; tries++) {
        struct sockaddr_in6 src;
        socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(sc->sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return -1;   /* timeout */
            if (errno == EINTR) continue;
            return -1;
        }
        if (n < 8) continue;

        /* Check type=echo_reply, id, seq. */
        if (buf[0] != ICMP6_ECHO_REPLY) continue;
        uint16_t rid = ((uint16_t)buf[4] << 8) | buf[5];
        uint16_t rseq = ((uint16_t)buf[6] << 8) | buf[7];
        if (rid != DIDAQT_ICMP_ID || rseq != seq) continue;

        /* Skip kernel auto-echo (payload == sent command).
         * Accept agent reply (starts with OK/ERR/PONG). */
        int payload_len = (int)n - 8;
        if (payload_len <= 0) continue;
        char *payload = (char *)(buf + 8);

        if (strncmp(payload, "OK", 2) == 0 ||
            strncmp(payload, "ERR", 3) == 0 ||
            strncmp(payload, "PONG", 4) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            long us = (t1.tv_sec - t0.tv_sec) * 1000000L
                    + (t1.tv_nsec - t0.tv_nsec) / 1000;

            if (resp_out && resp_sz > 0) {
                size_t cpy = (size_t)payload_len < resp_sz - 1
                           ? (size_t)payload_len : resp_sz - 1;
                memcpy(resp_out, payload, cpy);
                resp_out[cpy] = '\0';
            }
            return us;
        }
        /* Kernel auto-echo — skip and keep waiting. */
    }

    return -1;
}

static void switch_conn_close(switch_conn *sc)
{
    if (sc->sockfd >= 0) {
        close(sc->sockfd);
        sc->sockfd = -1;
    }
}

/* ------------------------------------------------------------------ */
/*  Switch handler                                                     */
/* ------------------------------------------------------------------ */

static int switch_handler(uint64_t sender_id,
                          int cur_in, int cur_out,
                          int new_in, int new_out,
                          void *user_data)
{
    switch_conn *sc = (switch_conn *)user_data;

    if (sc->sockfd < 0) {
        printf("  SWITCH UPDATE (log): sender_id=%lu  "
               "(%d,%d) -> (%d,%d)\n",
               (unsigned long)sender_id,
               cur_in, cur_out, new_in, new_out);
        return 0;
    }

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "UPDATE %lu %d %d %d %d",
             (unsigned long)sender_id,
             cur_in, cur_out, new_in, new_out);

    char resp[128] = {0};
    long us = switch_conn_send(sc, cmd, resp, sizeof(resp));
    if (us < 0) {
        fprintf(stderr, "  SWITCH UPDATE FAILED: no response\n");
        return -1;
    }

    printf("  SWITCH UPDATE: sender_id=%lu  (%d,%d) -> (%d,%d)  "
           "rtt=%ld us  resp=%s\n",
           (unsigned long)sender_id,
           cur_in, cur_out, new_in, new_out, us, resp);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        fprintf(stderr,
                "Usage: %s <topology.yaml> <heartbeat_port> "
                "[switch_ipv6]\n", argv[0]);
        return 1;
    }

    const char *topo_path  = argv[1];
    uint16_t hb_port       = (uint16_t)atoi(argv[2]);
    const char *agent_addr = (argc == 4) ? argv[3] : NULL;

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    /* ---- Open ICMPv6 channel to switch agent ---- */
    switch_conn sc;
    if (switch_conn_open(&sc, agent_addr) < 0) {
        fprintf(stderr, "Could not open ICMPv6 channel\n");
        return 1;
    }

    if (sc.sockfd >= 0) {
        char resp[64];
        long us = switch_conn_send(&sc, "PING", resp, sizeof(resp));
        if (us < 0) {
            fprintf(stderr, "Switch agent PING failed (no reply)\n");
            switch_conn_close(&sc);
            return 1;
        }
        printf("Switch agent PING OK: %s (rtt=%ld us)\n", resp, us);
    } else {
        printf("Running in log-only mode (no switch agent)\n");
    }

    /* ---- Initialise controller context ---- */
    didaqt_ctrl_ctx *ctx = NULL;
    if (didaqt_ctrl_init_ctx(&ctx) != DIDAQT_OK) {
        fprintf(stderr, "didaqt_ctrl_init_ctx failed\n");
        switch_conn_close(&sc);
        return 1;
    }

    printf("Loading topology: %s\n", topo_path);
    if (didaqt_ctrl_process_topology(topo_path, ctx) != DIDAQT_OK) {
        fprintf(stderr, "didaqt_ctrl_process_topology failed\n");
        didaqt_ctrl_destroy(ctx);
        switch_conn_close(&sc);
        return 1;
    }

    /* Print initial path state. */
    didaqt_path_info *paths = NULL;
    int path_count = 0;
    didaqt_ctrl_get_path_statuses(ctx, &paths, &path_count);
    printf("\nInitial paths (%d total):\n", path_count);
    for (int i = 0; i < path_count; i++) {
        const char *st;
        switch (paths[i].status) {
        case DIDAQT_PATH_USED:        st = "USED";        break;
        case DIDAQT_PATH_AVAILABLE:   st = "AVAILABLE";   break;
        case DIDAQT_PATH_TEMP_FAILED: st = "TEMP_FAILED"; break;
        case DIDAQT_PATH_FAILED:      st = "FAILED";      break;
        default:                      st = "?";            break;
        }
        printf("  [%d] sender=%s -> receiver=%s  %s\n",
               paths[i].path_id, paths[i].sender_name,
               paths[i].receiver_name, st);
    }
    free(paths);

    /* ---- Register switch handler ---- */
    didaqt_ctrl_register_handler(ctx, "tofino2", switch_handler, &sc);
    printf("\nSwitch handler registered for type 'tofino2'\n");

    /* ---- Open heartbeat listener (IPv6 dual-stack) ---- */
    int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        didaqt_ctrl_destroy(ctx);
        switch_conn_close(&sc);
        return 1;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int v6only = 0;
    setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr   = in6addr_any;
    addr.sin6_port   = htons(hb_port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        didaqt_ctrl_destroy(ctx);
        switch_conn_close(&sc);
        return 1;
    }

    printf("Controller listening for heartbeats on UDP port %u\n\n",
           hb_port);

    /* ---- Main loop ---- */
    uint8_t buf[6 + DIDAQT_MAX_SENDERS * 4];
    uint64_t hb_count = 0;

    while (running) {
        struct sockaddr_storage src;
        socklen_t src_len = sizeof(src);

        ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &src_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }
        if (n < 6) continue;

        hb_count++;

        uint32_t rid;
        uint16_t scnt;
        memcpy(&rid,  buf,     4); rid  = ntohl(rid);
        memcpy(&scnt, buf + 4, 2); scnt = ntohs(scnt);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        int rc = didaqt_ctrl_process_heartbeat(buf, (size_t)n, ctx);

        clock_gettime(CLOCK_MONOTONIC, &t1);
        long proc_us = (t1.tv_sec - t0.tv_sec) * 1000000L
                     + (t1.tv_nsec - t0.tv_nsec) / 1000;

        printf("[HB #%lu] receiver_id=%u senders=%u  proc=%ld us\n",
               (unsigned long)hb_count, rid, scnt, proc_us);

        if (rc != DIDAQT_OK) {
            printf("  (heartbeat processing error: rc=%d)\n", rc);
        }
    }

    close(sockfd);
    switch_conn_close(&sc);
    didaqt_ctrl_destroy(ctx);
    printf("\nController stopped after %lu heartbeats\n",
           (unsigned long)hb_count);
    return 0;
}
