#include "didaqt.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

/*
 * Hash set for O(1) blocked/scheduled sender lookups.
 * Open-addressing with linear probing; capacity is always a power of 2.
 * Entry value 0 = empty (sender_id 0 is rejected at the API boundary).
 */
#define HSET_CAP 512   /* must be power of 2, > DIDAQT_MAX_SENDERS */

_Static_assert((HSET_CAP & (HSET_CAP - 1)) == 0,
               "HSET_CAP must be a power of 2");
_Static_assert(HSET_CAP / 2 >= DIDAQT_MAX_SENDERS,
               "HSET_CAP/2 must be >= DIDAQT_MAX_SENDERS");

typedef struct {
    uint32_t entries[HSET_CAP];
    int      count;
} sender_hset;

static void hset_clear(sender_hset *s)
{
    memset(s->entries, 0, sizeof(s->entries));
    s->count = 0;
}

static int hset_contains(const sender_hset *s, uint32_t id)
{
    uint32_t idx = id & (HSET_CAP - 1);
    for (;;) {
        uint32_t e = s->entries[idx];
        if (e == 0)  return 0;
        if (e == id) return 1;
        idx = (idx + 1) & (HSET_CAP - 1);
    }
}

/* Internal insert — no load-factor check.  Used by hset_remove to
 * re-insert displaced entries (total count cannot increase). */
static void hset_reinsert(sender_hset *s, uint32_t id)
{
    uint32_t idx = id & (HSET_CAP - 1);
    for (;;) {
        uint32_t e = s->entries[idx];
        if (e == 0) {
            s->entries[idx] = id;
            s->count++;
            return;
        }
        if (e == id) return;  /* already present */
        idx = (idx + 1) & (HSET_CAP - 1);
    }
}

static int hset_insert(sender_hset *s, uint32_t id)
{
    if (id == 0) return -1;  /* 0 is the empty sentinel */
    if (s->count >= HSET_CAP / 2) return -1;  /* load factor limit */
    uint32_t idx = id & (HSET_CAP - 1);
    for (;;) {
        uint32_t e = s->entries[idx];
        if (e == 0) {
            s->entries[idx] = id;
            s->count++;
            return 1;  /* inserted */
        }
        if (e == id) return 0;  /* already present */
        idx = (idx + 1) & (HSET_CAP - 1);
    }
}

static void hset_remove(sender_hset *s, uint32_t id)
{
    if (id == 0) return;
    uint32_t idx = id & (HSET_CAP - 1);
    for (;;) {
        uint32_t e = s->entries[idx];
        if (e == 0) return;
        if (e == id) {
            /* Remove and re-insert displaced entries using the
             * internal reinsert (no load-factor check). */
            s->entries[idx] = 0;
            s->count--;
            uint32_t j = (idx + 1) & (HSET_CAP - 1);
            while (s->entries[j] != 0) {
                uint32_t displaced = s->entries[j];
                s->entries[j] = 0;
                s->count--;
                hset_reinsert(s, displaced);
                j = (j + 1) & (HSET_CAP - 1);
            }
            return;
        }
        idx = (idx + 1) & (HSET_CAP - 1);
    }
}

/* Collect all entries from the hash set into a flat array.
 * Caller must provide a buffer of at least HSET_CAP/2 entries. */
static int hset_to_array(const sender_hset *s, uint32_t *out)
{
    int n = 0;
    for (int i = 0; i < HSET_CAP; i++)
        if (s->entries[i] != 0)
            out[n++] = s->entries[i];
    return n;
}

struct didaqt_rx_ctx {
    uint32_t  r_id;

    /* Controller destination (IPv4 or IPv6). */
    struct sockaddr_storage ctrl_addr;
    socklen_t               ctrl_addr_len;
    int                     ctrl_addr_set;
    int                     sockfd;

    /* Heartbeat interval. */
    uint32_t  interval_ms;

    /* Scheduled and blocked sender sets (hash-based, O(1) operations). */
    sender_hset senders;
    sender_hset blocked;

    pthread_mutex_t lock;

    /* Background heartbeat thread. */
    pthread_t thread;
    atomic_int running;
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

        /* Snapshot and clear the scheduled and blocked sets. */
        pthread_mutex_lock(&ctx->lock);
        snap_count = hset_to_array(&ctx->senders, snap);
        hset_clear(&ctx->senders);
        hset_clear(&ctx->blocked);
        pthread_mutex_unlock(&ctx->lock);

        /* Always send a heartbeat — an empty one signals that the
         * receiver is alive but has no healthy sender connections. */
        int len = build_heartbeat(ctx, snap, snap_count,
                                  pkt, sizeof(pkt));
        if (len > 0) {
            ssize_t sent = sendto(ctx->sockfd, pkt, (size_t)len, 0,
                                  (struct sockaddr *)&ctx->ctrl_addr,
                                  ctx->ctrl_addr_len);
            if (sent < 0)
                write(STDERR_FILENO, "didaqt_rx: sendto failed\n", 25);
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

    c->r_id          = r_id;
    c->interval_ms   = DIDAQT_DEFAULT_HB_INTERVAL_MS;
    c->running       = 0;
    c->sockfd        = -1;
    c->ctrl_addr_set = 0;
    c->ctrl_addr_len = 0;

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

    /* Try IPv4 first, then IPv6. */
    struct sockaddr_in *a4 = (struct sockaddr_in *)&ctx->ctrl_addr;
    if (inet_pton(AF_INET, ip, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port   = htons(port);
        ctx->ctrl_addr_len = sizeof(*a4);
        ctx->ctrl_addr_set = 1;
        return DIDAQT_OK;
    }

    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ctx->ctrl_addr;
    if (inet_pton(AF_INET6, ip, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons(port);
        ctx->ctrl_addr_len = sizeof(*a6);
        ctx->ctrl_addr_set = 1;
        return DIDAQT_OK;
    }

    return DIDAQT_ERR;
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

    int af = ((struct sockaddr *)&ctx->ctrl_addr)->sa_family;
    ctx->sockfd = socket(af, SOCK_DGRAM, 0);
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
    if (!ctx || s_id == 0)
        return DIDAQT_ERR;

    pthread_mutex_lock(&ctx->lock);

    if (hset_contains(&ctx->blocked, s_id)) {
        pthread_mutex_unlock(&ctx->lock);
        return DIDAQT_OK;
    }

    int rc = hset_insert(&ctx->senders, s_id);
    pthread_mutex_unlock(&ctx->lock);

    return (rc < 0) ? DIDAQT_ERR_FULL : DIDAQT_OK;
}

int deschedule_heartbeat(uint32_t s_id, didaqt_rx_ctx *ctx)
{
    if (!ctx || s_id == 0)
        return DIDAQT_ERR;

    pthread_mutex_lock(&ctx->lock);

    hset_remove(&ctx->senders, s_id);
    if (hset_insert(&ctx->blocked, s_id) < 0)
        write(STDERR_FILENO,
              "didaqt_rx: blocked set full\n", 28);

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
