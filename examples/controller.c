/*
 * controller.c — DiDAQt controller node
 *
 * Loads a network topology from a YAML file, performs static
 * reachability analysis, then listens for heartbeat packets and
 * runs the failover state machine.
 *
 * When a switch agent address is provided, failover actions are
 * sent as TCP commands to the agent running on the Tofino, and
 * the round-trip time is measured and printed.
 *
 * Usage:
 *   ./controller <topology.yaml> <heartbeat_port> [switch_agent_host:port]
 *
 * Examples:
 *   ./controller topology.yaml 9000                     # log-only mode
 *   ./controller topology.yaml 9000 10.0.0.5:9200       # live switch updates
 *
 * Build:
 *   make build/controller
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
#include <netinet/tcp.h>
#include <netdb.h>

#include "didaqt.h"

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* ------------------------------------------------------------------ */
/*  Switch agent TCP connection                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    int  sockfd;       /* -1 = log-only mode (no agent) */
    char host[256];
    char port[16];
} switch_conn;

static int switch_conn_open(switch_conn *sc, const char *hostport)
{
    sc->sockfd = -1;
    if (!hostport) return 0;   /* log-only mode */

    /* Parse host:port. */
    const char *colon = strrchr(hostport, ':');
    if (!colon) {
        fprintf(stderr, "bad switch agent address (need host:port): %s\n",
                hostport);
        return -1;
    }
    size_t hlen = (size_t)(colon - hostport);
    if (hlen >= sizeof(sc->host)) hlen = sizeof(sc->host) - 1;
    memcpy(sc->host, hostport, hlen);
    sc->host[hlen] = '\0';
    strncpy(sc->port, colon + 1, sizeof(sc->port) - 1);

    struct addrinfo hints = {0}, *res;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(sc->host, sc->port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s:%s): %s\n",
                sc->host, sc->port, gai_strerror(rc));
        return -1;
    }

    sc->sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sc->sockfd < 0) {
        perror("socket (switch agent)");
        freeaddrinfo(res);
        return -1;
    }

    int opt = 1;
    setsockopt(sc->sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    if (connect(sc->sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect (switch agent)");
        close(sc->sockfd);
        sc->sockfd = -1;
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    printf("Connected to switch agent at %s:%s\n", sc->host, sc->port);
    return 0;
}

/*
 * Send a command, read the one-line response.
 * Returns the response latency in microseconds, or -1 on error.
 */
static long switch_conn_send(switch_conn *sc, const char *cmd)
{
    if (sc->sockfd < 0) return 0;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    size_t len = strlen(cmd);
    if (send(sc->sockfd, cmd, len, 0) != (ssize_t)len)
        return -1;

    /* Read response line. */
    char resp[256];
    int pos = 0;
    while (pos < (int)sizeof(resp) - 1) {
        ssize_t n = recv(sc->sockfd, resp + pos, 1, 0);
        if (n <= 0) return -1;
        if (resp[pos] == '\n') break;
        pos++;
    }
    resp[pos] = '\0';

    clock_gettime(CLOCK_MONOTONIC, &t1);
    long us = (t1.tv_sec - t0.tv_sec) * 1000000L
            + (t1.tv_nsec - t0.tv_nsec) / 1000;

    return us;
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
        /* Log-only mode. */
        printf("  SWITCH UPDATE (log): sender_id=%lu  "
               "(%d,%d) -> (%d,%d)\n",
               (unsigned long)sender_id,
               cur_in, cur_out, new_in, new_out);
        return 0;
    }

    /* Send real command to the switch agent. */
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "UPDATE %lu %d %d %d %d\n",
             (unsigned long)sender_id,
             cur_in, cur_out, new_in, new_out);

    long us = switch_conn_send(sc, cmd);
    if (us < 0) {
        fprintf(stderr, "  SWITCH UPDATE FAILED: send error\n");
        return -1;
    }

    printf("  SWITCH UPDATE: sender_id=%lu  (%d,%d) -> (%d,%d)  "
           "rtt=%ld us\n",
           (unsigned long)sender_id,
           cur_in, cur_out, new_in, new_out, us);
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
                "[switch_agent_host:port]\n", argv[0]);
        return 1;
    }

    const char *topo_path  = argv[1];
    uint16_t hb_port       = (uint16_t)atoi(argv[2]);
    const char *agent_addr = (argc == 4) ? argv[3] : NULL;

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    /* ---- Connect to switch agent (if specified) ---- */
    switch_conn sc;
    if (switch_conn_open(&sc, agent_addr) < 0) {
        fprintf(stderr, "Could not connect to switch agent\n");
        return 1;
    }

    if (sc.sockfd >= 0) {
        /* Verify with PING. */
        long us = switch_conn_send(&sc, "PING\n");
        if (us < 0) {
            fprintf(stderr, "Switch agent PING failed\n");
            switch_conn_close(&sc);
            return 1;
        }
        printf("Switch agent PING OK (rtt=%ld us)\n", us);
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

    /* ---- Process topology ---- */
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
