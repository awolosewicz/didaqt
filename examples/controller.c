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
 *   ./controller [-m miss] [-g grace_ms] [-s agent_map] <topology.yaml>
 *                <heartbeat_port> [switch_ipv6]
 *
 * Options:
 *   -m miss      Consecutive missed heartbeats before failover (default 3)
 *   -g grace_ms  Post-failover grace period in ms (default 1000)
 *   -s agent_map Per-switch agent map file, one "<switch_name> <ipv6>"
 *                per line.  UPDATE commands are routed to the named
 *                switch's agent and carry the switch name in the
 *                payload ("UPDATE <name> <sid> ...").  The positional
 *                switch_ipv6 argument keeps the legacy single-agent
 *                format ("UPDATE <sid> ...") for the Tofino artifact.
 *
 * Requires: CAP_NET_RAW for ICMPv6 switch communication (run with
 * sudo); not needed in log-only mode (no agent map or switch_ipv6).
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

static void handle_signal(__attribute__((unused)) int sig)
{
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
            snprintf(receivers[num_receivers++], DIDAQT_MAX_NAME,
                     "%s", paths[i].receiver_name);
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

#define DIDAQT_ICMP_ID   0xDDAA
#define DIDAQT_MAX_AGENTS 64

typedef struct {
    char                name[DIDAQT_MAX_NAME];
    struct sockaddr_in6 dest;
} agent_entry;

typedef struct {
    int                 sockfd;
    struct sockaddr_in6 dest;        /* legacy single-agent destination */
    uint16_t            seq;
    agent_entry         agents[DIDAQT_MAX_AGENTS];
    int                 num_agents;  /* > 0: per-switch agent map mode */
} switch_conn;

static int open_icmp6_socket(void)
{
    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0) {
        perror("socket (ICMPv6 raw)");
        return -1;
    }

    struct icmp6_filter filt;
    ICMP6_FILTER_SETBLOCKALL(&filt);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
    if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER,
                   &filt, sizeof(filt)) < 0)
        perror("setsockopt ICMP6_FILTER");

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO (ICMPv6)");
        close(fd);
        return -1;
    }
    return fd;
}

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

    sc->sockfd = open_icmp6_socket();
    return sc->sockfd < 0 ? -1 : 0;
}

/*
 * Load a per-switch agent map: one "<switch_name> <ipv6>" pair per
 * line.  UPDATE commands are then routed to the named switch's agent
 * (payload gains the switch name) instead of a single shared agent.
 */
static int switch_conn_load_map(switch_conn *sc, const char *path)
{
    memset(sc, 0, sizeof(*sc));
    sc->sockfd = -1;

    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return -1;
    }

    char name[DIDAQT_MAX_NAME], addr[128];
    while (fscanf(f, "%63s %127s", name, addr) == 2) {
        if (sc->num_agents >= DIDAQT_MAX_AGENTS) {
            fprintf(stderr, "agent map: too many entries (max %d)\n",
                    DIDAQT_MAX_AGENTS);
            fclose(f);
            return -1;
        }
        agent_entry *a = &sc->agents[sc->num_agents];
        snprintf(a->name, sizeof(a->name), "%s", name);
        if (inet_pton(AF_INET6, addr, &a->dest.sin6_addr) != 1) {
            fprintf(stderr, "agent map: bad IPv6 address for %s: %s\n",
                    name, addr);
            fclose(f);
            return -1;
        }
        a->dest.sin6_family = AF_INET6;
        sc->num_agents++;
    }
    fclose(f);

    if (sc->num_agents == 0) {
        fprintf(stderr, "agent map: no entries in %s\n", path);
        return -1;
    }

    sc->sockfd = open_icmp6_socket();
    return sc->sockfd < 0 ? -1 : 0;
}

static const struct sockaddr_in6 *find_agent(const switch_conn *sc,
                                             const char *name)
{
    for (int i = 0; i < sc->num_agents; i++)
        if (strcmp(sc->agents[i].name, name) == 0)
            return &sc->agents[i].dest;
    return NULL;
}

static size_t build_echo_request(uint8_t *pkt, size_t cap,
                                 uint16_t seq, const char *cmd)
{
    size_t cmd_len = strlen(cmd);
    size_t pkt_len = 8 + cmd_len;
    if (pkt_len > cap) {
        pkt_len = cap;
        cmd_len = pkt_len - 8;
    }

    memset(pkt, 0, 8);
    pkt[0] = ICMP6_ECHO_REQUEST;
    pkt[4] = (DIDAQT_ICMP_ID >> 8) & 0xFF;
    pkt[5] = DIDAQT_ICMP_ID & 0xFF;
    pkt[6] = (seq >> 8) & 0xFF;
    pkt[7] = seq & 0xFF;
    memcpy(pkt + 8, cmd, cmd_len);
    return pkt_len;
}

/* Fire-and-forget send (keepalives); replies are drained later. */
static void switch_conn_send_noreply(switch_conn *sc,
                                     const struct sockaddr_in6 *dest,
                                     const char *cmd)
{
    if (sc->sockfd < 0) return;
    if (!dest) dest = &sc->dest;

    uint8_t pkt[8 + 256];
    size_t pkt_len = build_echo_request(pkt, sizeof(pkt), sc->seq++, cmd);
    sendto(sc->sockfd, pkt, pkt_len, 0,
           (const struct sockaddr *)dest, sizeof(*dest));
}

static long switch_conn_send(switch_conn *sc,
                             const struct sockaddr_in6 *dest,
                             const char *cmd,
                             char *resp_out, size_t resp_sz)
{
    if (sc->sockfd < 0) return 0;
    if (!dest) dest = &sc->dest;

    uint16_t seq = sc->seq++;
    uint8_t pkt[8 + 256];
    size_t pkt_len = build_echo_request(pkt, sizeof(pkt), seq, cmd);

    /* Drain stale replies (from fire-and-forget keepalives and the
     * kernel's own echo responses) so the matching loop below only
     * has fresh packets to look at. */
    uint8_t drain[8 + 256];
    while (recvfrom(sc->sockfd, drain, sizeof(drain), MSG_DONTWAIT,
                    NULL, NULL) >= 0)
        ;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (sendto(sc->sockfd, pkt, pkt_len, 0,
               (const struct sockaddr *)dest, sizeof(*dest)) < 0)
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
/*  Failover event callback                                            */
/* ------------------------------------------------------------------ */

static void event_handler(const didaqt_event *ev,
                           __attribute__((unused)) void *user_data)
{
    switch (ev->type) {
    case DIDAQT_EVENT_FAILOVER:
        log_event("DECISION sender=%lu group=%u t_decision=%.3fms",
                  (unsigned long)ev->sender_id, ev->group_id,
                  ev->elapsed_ns / 1e6);
        break;
    case DIDAQT_EVENT_CONFIRMED:
        log_event("CONFIRMED sender=%lu group=%u t_confirm=%.3fms",
                  (unsigned long)ev->sender_id, ev->group_id,
                  ev->elapsed_ns / 1e6);
        break;
    case DIDAQT_EVENT_DEAD:
        if (ev->sender_id)
            log_event("DEAD sender=%lu group=%u",
                      (unsigned long)ev->sender_id, ev->group_id);
        else
            log_event("DEAD group=%u (all paths exhausted)", ev->group_id);
        break;
    case DIDAQT_EVENT_REVIVED:
        log_event("REVIVED sender=%lu group=%u",
                  (unsigned long)ev->sender_id, ev->group_id);
        break;
    }
}

/* ------------------------------------------------------------------ */
/*  Switch handler                                                     */
/* ------------------------------------------------------------------ */

static int switch_handler(const char *switch_name, uint64_t sender_id,
                          int cur_in, int cur_out,
                          int new_in, int new_out,
                          void *user_data)
{
    switch_conn *sc = (switch_conn *)user_data;

    if (sc->sockfd < 0) {
        log_event("SWITCH %s sender=%lu (%d,%d)->(%d,%d) [log-only]",
                  switch_name, (unsigned long)sender_id,
                  cur_in, cur_out, new_in, new_out);
        return 0;
    }

    const struct sockaddr_in6 *dest = NULL;
    char cmd[128];
    if (sc->num_agents > 0) {
        dest = find_agent(sc, switch_name);
        if (!dest) {
            log_event("SWITCH %s sender=%lu: no agent in map, skipped",
                      switch_name, (unsigned long)sender_id);
            return 0;
        }
        snprintf(cmd, sizeof(cmd), "UPDATE %s %lu %d %d %d %d",
                 switch_name, (unsigned long)sender_id,
                 cur_in, cur_out, new_in, new_out);
    } else {
        snprintf(cmd, sizeof(cmd), "UPDATE %lu %d %d %d %d",
                 (unsigned long)sender_id,
                 cur_in, cur_out, new_in, new_out);
    }

    char resp[128] = {0};
    long us = switch_conn_send(sc, dest, cmd, resp, sizeof(resp));
    if (us < 0) {
        log_event("SWITCH %s sender=%lu (%d,%d)->(%d,%d) FAILED",
                  switch_name, (unsigned long)sender_id,
                  cur_in, cur_out, new_in, new_out);
        return -1;
    }

    log_event("SWITCH %s sender=%lu (%d,%d)->(%d,%d) t_switch=%.3fms rtt=%ldus %s",
              switch_name, (unsigned long)sender_id,
              cur_in, cur_out, new_in, new_out, us / 2000.0, us, resp);
    return 0;
}

/* Keepalives prevent cold-path latency on the agent links.  In map
 * mode they are fire-and-forget so 32 agents do not serialize 32
 * reply round-trips inside the heartbeat loop. */
static void send_keepalives(switch_conn *sc)
{
    if (sc->sockfd < 0) return;
    if (sc->num_agents > 0) {
        for (int i = 0; i < sc->num_agents; i++)
            switch_conn_send_noreply(sc, &sc->agents[i].dest, "KA");
    } else {
        switch_conn_send(sc, NULL, "KA", NULL, 0);
    }
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    int miss_threshold = DIDAQT_DEFAULT_MISS_THRESHOLD;
    long grace_ms      = DIDAQT_DEFAULT_GRACE_PERIOD_NS / 1000000L;
    const char *agent_map = NULL;

    /* Parse optional flags. */
    while (argc > 1 && argv[1][0] == '-') {
        if (strcmp(argv[1], "-m") == 0 && argc > 2) {
            miss_threshold = atoi(argv[2]);
            argv += 2; argc -= 2;
        } else if (strcmp(argv[1], "-g") == 0 && argc > 2) {
            grace_ms = atol(argv[2]);
            argv += 2; argc -= 2;
        } else if (strcmp(argv[1], "-s") == 0 && argc > 2) {
            agent_map = argv[2];
            argv += 2; argc -= 2;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[1]);
            return 1;
        }
    }

    if (argc < 3 || argc > 4) {
        fprintf(stderr,
                "Usage: %s [-m miss] [-g grace_ms] [-s agent_map] "
                "<topology.yaml> <heartbeat_port> [switch_ipv6]\n", argv[0]);
        return 1;
    }

    const char *topo_path  = argv[1];
    uint16_t hb_port       = (uint16_t)atoi(argv[2]);
    const char *agent_addr = (argc == 4) ? argv[3] : NULL;

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    /* ---- Open ICMPv6 channel to switch agent(s) ---- */
    switch_conn sc;
    if (agent_map) {
        if (switch_conn_load_map(&sc, agent_map) < 0) {
            fprintf(stderr, "Could not load agent map\n");
            return 1;
        }
    } else if (switch_conn_open(&sc, agent_addr) < 0) {
        fprintf(stderr, "Could not open ICMPv6 channel\n");
        return 1;
    }

    if (sc.num_agents > 0) {
        int ok = 0;
        for (int i = 0; i < sc.num_agents; i++) {
            char resp[64];
            long us = switch_conn_send(&sc, &sc.agents[i].dest,
                                       "PING", resp, sizeof(resp));
            if (us < 0)
                fprintf(stderr, "agent %s: PING failed (no reply)\n",
                        sc.agents[i].name);
            else
                ok++;
        }
        fprintf(stderr, "Switch agents: %d/%d PING OK\n", ok, sc.num_agents);
        if (ok == 0) {
            switch_conn_close(&sc);
            return 1;
        }
    } else if (sc.sockfd >= 0) {
        char resp[64];
        long us = switch_conn_send(&sc, NULL, "PING", resp, sizeof(resp));
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

    didaqt_ctrl_set_miss_threshold(ctx, miss_threshold);
    didaqt_ctrl_set_grace_period(ctx, grace_ms * 1000000L);
    didaqt_ctrl_set_event_callback(ctx, event_handler, NULL);

    fprintf(stderr, "Loading topology: %s\n", topo_path);
    if (didaqt_ctrl_process_topology(topo_path, ctx) != DIDAQT_OK) {
        fprintf(stderr, "didaqt_ctrl_process_topology failed\n");
        didaqt_ctrl_destroy(ctx);
        switch_conn_close(&sc);
        return 1;
    }

    g_ctx = ctx;

    /* ---- Register switch handler ---- */
    if (didaqt_ctrl_register_handler(ctx, "tofino2",
                                     switch_handler, &sc) != DIDAQT_OK) {
        fprintf(stderr, "didaqt_ctrl_register_handler failed\n");
        didaqt_ctrl_destroy(ctx);
        switch_conn_close(&sc);
        return 1;
    }

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

    /* Use a short receive timeout so the main loop can send periodic
     * keepalives to the switch agent between heartbeats. */
    struct timeval hb_tv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100ms */
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                   &hb_tv, sizeof(hb_tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO (heartbeat)");
        close(sockfd);
        didaqt_ctrl_destroy(ctx);
        switch_conn_close(&sc);
        return 1;
    }

    /* Clear screen and draw initial display. */
    printf("\033[2J");
    draw_display(hb_port);

    /* ---- Main loop ---- */
    uint8_t buf[6 + DIDAQT_MAX_SENDERS * 4];
    struct timespec last_ka;
    clock_gettime(CLOCK_MONOTONIC, &last_ka);

    while (running) {
        struct sockaddr_storage src;
        socklen_t src_len = sizeof(src);

        ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &src_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Check if it's time for a keepalive. */
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                long ka_elapsed = (now.tv_sec  - last_ka.tv_sec) * 1000000000L
                                + (now.tv_nsec - last_ka.tv_nsec);
                if (ka_elapsed >= 1000000000L && sc.sockfd >= 0) {
                    send_keepalives(&sc);
                    last_ka = now;
                }
                continue;
            }
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }
        if (n < 6) continue;

        didaqt_ctrl_process_heartbeat(buf, (size_t)n, ctx);

        /* Send a keepalive if 1 second has passed since the last one. */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long ka_elapsed = (now.tv_sec  - last_ka.tv_sec) * 1000000000L
                        + (now.tv_nsec - last_ka.tv_nsec);
        if (ka_elapsed >= 1000000000L && sc.sockfd >= 0) {
            send_keepalives(&sc);
            last_ka = now;
        }

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
