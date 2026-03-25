/*
 * controller.c — DiDAQt controller node
 *
 * Loads a network topology from a YAML file, performs static
 * reachability analysis, then listens for heartbeat packets and
 * runs the failover state machine.
 *
 * Displays a live terminal UI showing sender routing and a
 * scrolling log of failover events.
 *
 * Usage:
 *   ./controller <topology.yaml> <heartbeat_port> [switch_ipv6]
 *
 * Requires: CAP_NET_RAW (run with sudo).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
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
/*  Event log ring buffer                                              */
/* ------------------------------------------------------------------ */

#define LOG_LINES    16
#define LOG_LINE_LEN 120

static char   event_log[LOG_LINES][LOG_LINE_LEN];
static int    log_next = 0;     /* next write slot */
static int    log_count = 0;    /* total entries written */

static void log_event(const char *fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);

    char *line = event_log[log_next % LOG_LINES];
    int pos = snprintf(line, LOG_LINE_LEN, "[%02d:%02d:%02d] ",
                       tm->tm_hour, tm->tm_min, tm->tm_sec);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line + pos, LOG_LINE_LEN - pos, fmt, ap);
    va_end(ap);

    log_next = (log_next + 1) % LOG_LINES;
    if (log_count < LOG_LINES) log_count++;
}

/* ------------------------------------------------------------------ */
/*  Terminal display                                                   */
/* ------------------------------------------------------------------ */

static didaqt_ctrl_ctx *g_ctx = NULL;   /* for display access */

static void draw_display(uint16_t hb_port)
{
    if (!g_ctx) return;

    didaqt_path_info *paths = NULL;
    int path_count = 0;
    didaqt_ctrl_get_path_statuses(g_ctx, &paths, &path_count);

    printf("\033[H");   /* cursor home */

    printf("\033[1m  DiDAQt Controller\033[0m — UDP port %u\033[K\n",
           hb_port);
    printf("  ══════════════════════════════════════════════════\033[K\n");

    /* Collect unique receiver names from Used paths. */
    char receivers[64][DIDAQT_MAX_NAME];
    int num_receivers = 0;
    for (int i = 0; i < path_count; i++) {
        int found = 0;
        for (int r = 0; r < num_receivers; r++) {
            if (strcmp(receivers[r], paths[i].receiver_name) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && num_receivers < 64)
            strncpy(receivers[num_receivers++],
                    paths[i].receiver_name, DIDAQT_MAX_NAME - 1);
    }

    /* For each receiver, show which senders are routed to it. */
    for (int r = 0; r < num_receivers; r++) {
        printf("  \033[1m%-10s\033[0m:", receivers[r]);
        int col = 0;
        for (int i = 0; i < path_count; i++) {
            if (paths[i].status != DIDAQT_PATH_USED) continue;
            if (strcmp(paths[i].receiver_name, receivers[r]) != 0) continue;
            if (col > 0 && col % 12 == 0)
                printf("\n            ");
            printf(" %s", paths[i].sender_name);
            col++;
        }
        if (col == 0)
            printf(" \033[2m(none)\033[0m");
        printf("\033[K\n");
    }

    printf("  ══════════════════════════════════════════════════\033[K\n");
    printf("  \033[1mEvent Log:\033[0m\033[K\n");

    /* Print log entries oldest-first. */
    int start = (log_count < LOG_LINES) ? 0 : log_next;
    int count = (log_count < LOG_LINES) ? log_count : LOG_LINES;
    for (int i = 0; i < count; i++) {
        int idx = (start + i) % LOG_LINES;
        printf("  %s\033[K\n", event_log[idx]);
    }
    /* Pad remaining log lines to keep display stable. */
    for (int i = count; i < LOG_LINES; i++)
        printf("  \033[K\n");

    printf("\033[J");   /* clear below */
    fflush(stdout);

    free(paths);
}

/* ------------------------------------------------------------------ */
/*  ICMPv6 switch agent connection                                     */
/* ------------------------------------------------------------------ */

#define DIDAQT_ICMP_ID  0xDDAA

typedef struct {
    int                sockfd;
    struct sockaddr_in6 dest;
    uint16_t           seq;
} switch_conn;

static int switch_conn_open(switch_conn *sc, const char *addr)
{
    memset(sc, 0, sizeof(*sc));
    sc->sockfd = -1;
    if (!addr) return 0;

    if (inet_pton(AF_INET6, addr, &sc->dest.sin6_addr) != 1) {
        fprintf(stderr, "bad IPv6 address: %s\n", addr);
        return -1;
    }
    sc->dest.sin6_family = AF_INET6;

    sc->sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sc->sockfd < 0) {
        perror("socket (ICMPv6 raw)");
        return -1;
    }

    struct icmp6_filter filt;
    ICMP6_FILTER_SETBLOCKALL(&filt);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
    setsockopt(sc->sockfd, IPPROTO_ICMPV6, ICMP6_FILTER,
               &filt, sizeof(filt));

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sc->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return 0;
}

static long switch_conn_send(switch_conn *sc, const char *cmd,
                             char *resp_out, size_t resp_sz)
{
    if (sc->sockfd < 0) return 0;

    uint16_t seq = sc->seq++;
    size_t cmd_len = strlen(cmd);

    size_t pkt_len = 8 + cmd_len;
    uint8_t pkt[8 + 256];
    if (pkt_len > sizeof(pkt)) pkt_len = sizeof(pkt);

    memset(pkt, 0, 8);
    pkt[0] = ICMP6_ECHO_REQUEST;
    pkt[4] = (DIDAQT_ICMP_ID >> 8) & 0xFF;
    pkt[5] = DIDAQT_ICMP_ID & 0xFF;
    pkt[6] = (seq >> 8) & 0xFF;
    pkt[7] = seq & 0xFF;
    memcpy(pkt + 8, cmd, cmd_len);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (sendto(sc->sockfd, pkt, pkt_len, 0,
               (struct sockaddr *)&sc->dest, sizeof(sc->dest)) < 0)
        return -1;

    uint8_t buf[8 + 256];
    for (int tries = 0; tries < 10; tries++) {
        struct sockaddr_in6 src;
        socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(sc->sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
            if (errno == EINTR) continue;
            return -1;
        }
        if (n < 8) continue;
        if (buf[0] != ICMP6_ECHO_REPLY) continue;
        uint16_t rid = ((uint16_t)buf[4] << 8) | buf[5];
        uint16_t rseq = ((uint16_t)buf[6] << 8) | buf[7];
        if (rid != DIDAQT_ICMP_ID || rseq != seq) continue;

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
        log_event("FAILOVER sender=%lu (%d,%d)->(%d,%d) [log-only]",
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
        log_event("FAILOVER sender=%lu (%d,%d)->(%d,%d) FAILED",
                  (unsigned long)sender_id,
                  cur_in, cur_out, new_in, new_out);
        return -1;
    }

    log_event("FAILOVER sender=%lu (%d,%d)->(%d,%d) rtt=%ldus %s",
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
        fprintf(stderr, "Switch agent PING OK: %s (rtt=%ld us)\n", resp, us);
    } else {
        fprintf(stderr, "Running in log-only mode (no switch agent)\n");
    }

    /* ---- Initialise controller context ---- */
    didaqt_ctrl_ctx *ctx = NULL;
    if (didaqt_ctrl_init_ctx(&ctx) != DIDAQT_OK) {
        fprintf(stderr, "didaqt_ctrl_init_ctx failed\n");
        switch_conn_close(&sc);
        return 1;
    }

    fprintf(stderr, "Loading topology: %s\n", topo_path);
    if (didaqt_ctrl_process_topology(topo_path, ctx) != DIDAQT_OK) {
        fprintf(stderr, "didaqt_ctrl_process_topology failed\n");
        didaqt_ctrl_destroy(ctx);
        switch_conn_close(&sc);
        return 1;
    }

    g_ctx = ctx;

    /* ---- Register switch handler ---- */
    didaqt_ctrl_register_handler(ctx, "tofino2", switch_handler, &sc);

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

    fprintf(stderr, "Listening on UDP port %u — starting display.\n\n",
            hb_port);

    /* Clear screen and draw initial display. */
    printf("\033[2J");
    draw_display(hb_port);

    /* ---- Main loop ---- */
    uint8_t buf[6 + DIDAQT_MAX_SENDERS * 4];

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

        didaqt_ctrl_process_heartbeat(buf, (size_t)n, ctx);

        /* Redraw after each heartbeat. */
        draw_display(hb_port);
    }

    close(sockfd);
    switch_conn_close(&sc);
    didaqt_ctrl_destroy(ctx);
    printf("\033[2J\033[H");
    printf("Controller stopped.\n");
    return 0;
}
