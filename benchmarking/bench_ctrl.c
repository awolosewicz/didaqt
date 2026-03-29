/*
 * bench_ctrl.c — Benchmark the DiDAQt controller API
 *
 * Measures preprocessing time (topology parsing + path finding) and
 * failover decision time (heartbeat processing to handler invocation).
 *
 * Usage:
 *   ./bench_ctrl <topology.yaml> <switch_count>
 *
 * Output (to stdout):
 *   Line 1:  active_receivers,switch_count,preprocess_ns
 *   Lines 2-11: decision_ns (one per trial, 10 total)
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -Werror -std=c11 -pthread -Iinclude -o bench_ctrl \
 *       benchmarking/bench_ctrl.c -Lbuild -ldidaqt -lyaml -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "didaqt.h"

#define NUM_TRIALS 10
#define MAX_SENDERS_PER_RECV 256

/* ------------------------------------------------------------------ */
/*  Event callback — captures failover decision time                   */
/* ------------------------------------------------------------------ */

static long g_decision_ns;

static void event_cb(const didaqt_event *ev,
                      __attribute__((unused)) void *ud)
{
    if (ev->type == DIDAQT_EVENT_FAILOVER)
        g_decision_ns = ev->elapsed_ns;
}

/* ------------------------------------------------------------------ */
/*  Mock switch handler — instant return                               */
/* ------------------------------------------------------------------ */

static int mock_handler(__attribute__((unused)) uint64_t sid,
                         __attribute__((unused)) int ci,
                         __attribute__((unused)) int co,
                         __attribute__((unused)) int ni,
                         __attribute__((unused)) int no,
                         __attribute__((unused)) void *ud)
{
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Heartbeat helpers                                                   */
/* ------------------------------------------------------------------ */

static int build_hb(uint32_t rid, const uint32_t *sids, int cnt,
                     uint8_t *buf, size_t sz)
{
    size_t need = 6 + (size_t)cnt * 4;
    if (need > sz) return -1;
    uint32_t r = htonl(rid);
    uint16_t c = htons((uint16_t)cnt);
    memcpy(buf, &r, 4);
    memcpy(buf + 4, &c, 2);
    for (int i = 0; i < cnt; i++) {
        uint32_t s = htonl(sids[i]);
        memcpy(buf + 6 + i * 4, &s, 4);
    }
    return (int)need;
}

/* ------------------------------------------------------------------ */
/*  Receiver→sender map: built once, updated incrementally              */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t receiver_id;
    uint32_t senders[MAX_SENDERS_PER_RECV];
    int      count;
} recv_bucket;

static recv_bucket *buckets;
static int          num_buckets;
static int          max_buckets;

/* rid_to_bucket[rid] = index into buckets[], -1 if none. */
static int *rid_to_bucket;
static int  rid_to_bucket_sz;

/* sid_to_rid[sid] = current receiver_id for sender sid.
 * Allows O(1) lookup instead of scanning all buckets. */
static uint32_t *sid_to_rid;
static int        sid_to_rid_sz;

static int ensure_rid_lookup(uint32_t rid)
{
    if ((int)rid < rid_to_bucket_sz) return 0;
    int new_sz = (int)rid + 1;
    int *tmp = realloc(rid_to_bucket, new_sz * sizeof(int));
    if (!tmp) return -1;
    memset(tmp + rid_to_bucket_sz, 0xff,
           (new_sz - rid_to_bucket_sz) * sizeof(int));
    rid_to_bucket = tmp;
    rid_to_bucket_sz = new_sz;
    return 0;
}

static int ensure_sid_lookup(uint32_t sid)
{
    if ((int)sid < sid_to_rid_sz) return 0;
    int new_sz = (int)sid + 1;
    uint32_t *tmp = realloc(sid_to_rid, new_sz * sizeof(uint32_t));
    if (!tmp) return -1;
    memset(tmp + sid_to_rid_sz, 0, (new_sz - sid_to_rid_sz) * sizeof(uint32_t));
    sid_to_rid = tmp;
    sid_to_rid_sz = new_sz;
    return 0;
}

static int get_or_create_bucket(uint32_t rid)
{
    if (ensure_rid_lookup(rid) < 0) return -1;
    int b = rid_to_bucket[rid];
    if (b >= 0) return b;

    if (num_buckets >= max_buckets) {
        int new_max = max_buckets ? max_buckets * 2 : 256;
        recv_bucket *tmp = realloc(buckets, new_max * sizeof(recv_bucket));
        if (!tmp) return -1;
        buckets = tmp;
        max_buckets = new_max;
    }
    b = num_buckets++;
    buckets[b].receiver_id = rid;
    buckets[b].count = 0;
    rid_to_bucket[rid] = b;
    return b;
}

/* Build map once from path statuses after preprocessing. */
static int build_initial_map(didaqt_ctrl_ctx *ctx)
{
    didaqt_path_info *paths;
    int path_count;
    if (didaqt_ctrl_get_path_statuses(ctx, &paths, &path_count) != DIDAQT_OK)
        return -1;

    num_buckets = 0;

    for (int i = 0; i < path_count; i++) {
        if (paths[i].status != DIDAQT_PATH_USED) continue;

        uint32_t rid = paths[i].receiver_id;
        uint32_t sid = (uint32_t)paths[i].sender_id;

        int b = get_or_create_bucket(rid);
        if (b < 0) { free(paths); return -1; }

        if (buckets[b].count < MAX_SENDERS_PER_RECV)
            buckets[b].senders[buckets[b].count++] = sid;

        if (ensure_sid_lookup(sid) < 0) { free(paths); return -1; }
        sid_to_rid[sid] = rid;
    }

    free(paths);
    return 0;
}

/* Move a sender from its current bucket to a new one.
 * Called after a failover to keep the map in sync. */
static void move_sender(uint32_t sid, uint32_t new_rid)
{
    /* Remove from old bucket. */
    if ((int)sid < sid_to_rid_sz && sid_to_rid[sid] != 0) {
        uint32_t old_rid = sid_to_rid[sid];
        if ((int)old_rid < rid_to_bucket_sz && rid_to_bucket[old_rid] >= 0) {
            recv_bucket *ob = &buckets[rid_to_bucket[old_rid]];
            for (int i = 0; i < ob->count; i++) {
                if (ob->senders[i] == sid) {
                    ob->senders[i] = ob->senders[--ob->count];
                    break;
                }
            }
        }
    }

    /* Add to new bucket. */
    int b = get_or_create_bucket(new_rid);
    if (b >= 0 && buckets[b].count < MAX_SENDERS_PER_RECV)
        buckets[b].senders[buckets[b].count++] = sid;

    if ((int)sid < sid_to_rid_sz)
        sid_to_rid[sid] = new_rid;
}

/* Send a heartbeat for a single receiver from the current map. */
static void send_one_heartbeat(didaqt_ctrl_ctx *ctx, uint32_t rid)
{
    if ((int)rid >= rid_to_bucket_sz) return;
    int b = rid_to_bucket[rid];
    if (b < 0) return;

    uint8_t buf[6 + MAX_SENDERS_PER_RECV * 4];
    int len = build_hb(rid, buckets[b].senders, buckets[b].count,
                       buf, sizeof(buf));
    if (len > 0)
        didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);
}

/* Send heartbeats from all receivers (used only for initial "seen" setup). */
static void send_all_heartbeats(didaqt_ctrl_ctx *ctx)
{
    uint8_t buf[6 + MAX_SENDERS_PER_RECV * 4];
    for (int i = 0; i < num_buckets; i++) {
        int len = build_hb(buckets[i].receiver_id,
                           buckets[i].senders, buckets[i].count,
                           buf, sizeof(buf));
        if (len > 0)
            didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);
    }
}

/* Build heartbeat for a receiver, excluding one sender. */
static int build_hb_without(uint32_t rid, uint32_t exclude_sid,
                              uint8_t *buf, size_t sz)
{
    if ((int)rid >= rid_to_bucket_sz) return -1;
    int b = rid_to_bucket[rid];
    if (b < 0) return -1;

    uint32_t filtered[MAX_SENDERS_PER_RECV];
    int cnt = 0;
    for (int j = 0; j < buckets[b].count; j++) {
        if (buckets[b].senders[j] != exclude_sid)
            filtered[cnt++] = buckets[b].senders[j];
    }
    return build_hb(rid, filtered, cnt, buf, sz);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <topology.yaml> <switch_count>\n", argv[0]);
        return 1;
    }

    const char *yaml_path = argv[1];
    int switch_count = atoi(argv[2]);

    /* ---- Init controller ---- */
    didaqt_ctrl_ctx *ctx;
    if (didaqt_ctrl_init_ctx(&ctx) != DIDAQT_OK) {
        fprintf(stderr, "init_ctx failed\n");
        return 1;
    }

    didaqt_ctrl_set_miss_threshold(ctx, 1);
    didaqt_ctrl_set_grace_period(ctx, 0);
    didaqt_ctrl_set_event_callback(ctx, event_cb, NULL);

    /* ---- Measure preprocessing ---- */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = didaqt_ctrl_process_topology(yaml_path, ctx);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (rc != DIDAQT_OK) {
        fprintf(stderr, "process_topology failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }

    long preprocess_ns = (t1.tv_sec - t0.tv_sec) * 1000000000L
                        + (t1.tv_nsec - t0.tv_nsec);

    /* Register mock handler. */
    if (didaqt_ctrl_register_handler(ctx, "tofino2", mock_handler, NULL)
        != DIDAQT_OK) {
        fprintf(stderr, "register_handler failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }

    /* ---- Build receiver→sender map once ---- */
    if (build_initial_map(ctx) < 0) {
        fprintf(stderr, "build_initial_map failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }
    int active_recv = num_buckets;

    /* ---- Mark all senders as "seen" ---- */
    send_all_heartbeats(ctx);
    send_all_heartbeats(ctx);

    /* ---- Run failover trials ---- */
    uint32_t target_sid = 1;  /* Always fail S1 */
    long decisions[NUM_TRIALS];

    for (int t = 0; t < NUM_TRIALS; t++) {
        /* Look up sender's current receiver via O(1) map. */
        uint32_t old_rid = ((int)target_sid < sid_to_rid_sz)
                           ? sid_to_rid[target_sid] : 0;
        if (old_rid == 0) {
            fprintf(stderr, "trial %d: sender %u has no USED path\n",
                    t, target_sid);
            decisions[t] = -1;
            continue;
        }

        /* Build heartbeat from old_rid WITHOUT target sender. */
        uint8_t buf[6 + MAX_SENDERS_PER_RECV * 4];
        int len = build_hb_without(old_rid, target_sid, buf, sizeof(buf));
        if (len < 0) {
            fprintf(stderr, "trial %d: build_hb_without failed\n", t);
            decisions[t] = -1;
            continue;
        }

        g_decision_ns = 0;
        didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);
        decisions[t] = g_decision_ns;

        /* Find where the sender moved by querying path statuses
         * for just this sender (small query). */
        didaqt_path_info *paths;
        int path_count;
        didaqt_ctrl_get_path_statuses(ctx, &paths, &path_count);
        uint32_t new_rid = 0;
        for (int i = 0; i < path_count; i++) {
            if ((uint32_t)paths[i].sender_id == target_sid &&
                paths[i].status == DIDAQT_PATH_USED) {
                new_rid = paths[i].receiver_id;
                break;
            }
        }

        /* Also find all group members that moved (group failover moves
         * all 4 senders together). */
        uint32_t moved_sids[MAX_SENDERS_PER_RECV];
        int n_moved = 0;
        if (new_rid != 0 && new_rid != old_rid) {
            for (int i = 0; i < path_count; i++) {
                if (paths[i].status != DIDAQT_PATH_USED) continue;
                uint32_t sid = (uint32_t)paths[i].sender_id;
                if ((int)sid < sid_to_rid_sz &&
                    sid_to_rid[sid] == old_rid &&
                    paths[i].receiver_id == new_rid &&
                    n_moved < MAX_SENDERS_PER_RECV)
                    moved_sids[n_moved++] = sid;
            }
        }
        free(paths);

        /* Incrementally update the map. */
        for (int i = 0; i < n_moved; i++)
            move_sender(moved_sids[i], new_rid);

        /* Confirm: send heartbeats only for the two affected receivers. */
        send_one_heartbeat(ctx, old_rid);
        if (new_rid != 0 && new_rid != old_rid)
            send_one_heartbeat(ctx, new_rid);
        /* Second round to confirm TempFailed→Failed. */
        send_one_heartbeat(ctx, old_rid);
        if (new_rid != 0 && new_rid != old_rid)
            send_one_heartbeat(ctx, new_rid);
    }

    /* ---- Output results ---- */
    fprintf(stderr, "active_receivers=%d switches_per_path=%d preprocess=%.3fms\n",
            active_recv, switch_count, preprocess_ns / 1e6);

    printf("%d,%d,%ld\n", active_recv, switch_count, preprocess_ns);

    for (int t = 0; t < NUM_TRIALS; t++) {
        if (decisions[t] < 0)
            printf("FAIL\n");
        else
            printf("%ld\n", decisions[t]);
    }

    didaqt_ctrl_destroy(ctx);
    free(buckets);
    free(rid_to_bucket);
    free(sid_to_rid);
    return 0;
}
