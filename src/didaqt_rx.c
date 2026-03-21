#include "didaqt.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

struct didaqt_rx_ctx {
    uint32_t  r_id;

    /* Controller destination. */
    struct sockaddr_in ctrl_addr;
    int                ctrl_addr_set;
    int                sockfd;

    /* Heartbeat interval. */
    uint32_t  interval_ms;

    /* Scheduled sender IDs for the current interval. */
    uint32_t  senders[DIDAQT_MAX_SENDERS];
    int       sender_count;
    pthread_mutex_t lock;

    /* Background heartbeat thread. */
    pthread_t thread;
    int       running;
};

/* ------------------------------------------------------------------ */
/*  Heartbeat thread                                                   */
/* ------------------------------------------------------------------ */

/*
 * Build a heartbeat packet into buf and return its length.
 *
 * Wire format (all fields network byte order):
 *   uint32_t  receiver_id
 *   uint16_t  sender_count
 *   uint32_t  sender_ids[sender_count]
 */
static int build_heartbeat(const didaqt_rx_ctx *ctx,
                           uint32_t *senders, int count,
                           uint8_t *buf, size_t buf_len)
{
    size_t needed = sizeof(uint32_t) + sizeof(uint16_t)
                  + (size_t)count * sizeof(uint32_t);
    if (needed > buf_len)
        return -1;

    uint8_t *p = buf;

    uint32_t rid_n = htonl(ctx->r_id);
    memcpy(p, &rid_n, sizeof(rid_n));
    p += sizeof(rid_n);

    uint16_t cnt_n = htons((uint16_t)count);
    memcpy(p, &cnt_n, sizeof(cnt_n));
    p += sizeof(cnt_n);

    for (int i = 0; i < count; i++) {
        uint32_t sid_n = htonl(senders[i]);
        memcpy(p, &sid_n, sizeof(sid_n));
        p += sizeof(sid_n);
    }

    return (int)(p - buf);
}

static void *heartbeat_loop(void *arg)
{
    didaqt_rx_ctx *ctx = (didaqt_rx_ctx *)arg;

    struct timespec ts;
    ts.tv_sec  = ctx->interval_ms / 1000;
    ts.tv_nsec = (ctx->interval_ms % 1000) * 1000000L;

    uint8_t  pkt[6 + DIDAQT_MAX_SENDERS * 4];
    uint32_t snap[DIDAQT_MAX_SENDERS];
    int      snap_count;

    while (ctx->running) {
        nanosleep(&ts, NULL);

        /* Snapshot and clear the scheduled set. */
        pthread_mutex_lock(&ctx->lock);
        snap_count = ctx->sender_count;
        if (snap_count > 0)
            memcpy(snap, ctx->senders, snap_count * sizeof(uint32_t));
        ctx->sender_count = 0;
        pthread_mutex_unlock(&ctx->lock);

        /* Always send a heartbeat — an empty one signals that the
         * receiver is alive but has no healthy sender connections. */
        int len = build_heartbeat(ctx, snap, snap_count,
                                  pkt, sizeof(pkt));
        if (len > 0) {
            sendto(ctx->sockfd, pkt, (size_t)len, 0,
                   (struct sockaddr *)&ctx->ctrl_addr,
                   sizeof(ctx->ctrl_addr));
        }
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

int didaqt_rx_init_ctx(uint32_t r_id, didaqt_rx_ctx **ctx)
{
    if (!ctx)
        return DIDAQT_ERR;

    didaqt_rx_ctx *c = calloc(1, sizeof(*c));
    if (!c)
        return DIDAQT_ERR;

    c->r_id         = r_id;
    c->interval_ms  = DIDAQT_DEFAULT_HB_INTERVAL_MS;
    c->sender_count = 0;
    c->running      = 0;
    c->sockfd       = -1;
    c->ctrl_addr_set = 0;

    if (pthread_mutex_init(&c->lock, NULL) != 0) {
        free(c);
        return DIDAQT_ERR;
    }

    *ctx = c;
    return DIDAQT_OK;
}

int didaqt_rx_set_controller(didaqt_rx_ctx *ctx,
                             const char *ip, uint16_t port)
{
    if (!ctx || !ip)
        return DIDAQT_ERR;

    memset(&ctx->ctrl_addr, 0, sizeof(ctx->ctrl_addr));
    ctx->ctrl_addr.sin_family = AF_INET;
    ctx->ctrl_addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, ip, &ctx->ctrl_addr.sin_addr) != 1)
        return DIDAQT_ERR;

    ctx->ctrl_addr_set = 1;
    return DIDAQT_OK;
}

int didaqt_rx_set_interval(didaqt_rx_ctx *ctx, uint32_t interval_ms)
{
    if (!ctx || interval_ms == 0)
        return DIDAQT_ERR;
    ctx->interval_ms = interval_ms;
    return DIDAQT_OK;
}

int didaqt_rx_start(didaqt_rx_ctx *ctx)
{
    if (!ctx || !ctx->ctrl_addr_set || ctx->running)
        return DIDAQT_ERR;

    ctx->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->sockfd < 0)
        return DIDAQT_ERR;

    ctx->running = 1;

    if (pthread_create(&ctx->thread, NULL, heartbeat_loop, ctx) != 0) {
        ctx->running = 0;
        close(ctx->sockfd);
        ctx->sockfd = -1;
        return DIDAQT_ERR;
    }

    return DIDAQT_OK;
}

int schedule_heartbeat(uint32_t s_id, didaqt_rx_ctx *ctx)
{
    if (!ctx)
        return DIDAQT_ERR;

    pthread_mutex_lock(&ctx->lock);

    /* Check if already scheduled to avoid duplicates. */
    for (int i = 0; i < ctx->sender_count; i++) {
        if (ctx->senders[i] == s_id) {
            pthread_mutex_unlock(&ctx->lock);
            return DIDAQT_OK;
        }
    }

    if (ctx->sender_count >= DIDAQT_MAX_SENDERS) {
        pthread_mutex_unlock(&ctx->lock);
        return DIDAQT_ERR_FULL;
    }

    ctx->senders[ctx->sender_count++] = s_id;

    pthread_mutex_unlock(&ctx->lock);
    return DIDAQT_OK;
}

void didaqt_rx_stop(didaqt_rx_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->running) {
        ctx->running = 0;
        pthread_join(ctx->thread, NULL);
    }

    if (ctx->sockfd >= 0)
        close(ctx->sockfd);

    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}
