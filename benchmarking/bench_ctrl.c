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
 *   Line 1:  rounded_paths,switch_count,preprocess_ns
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
#define MAX_RECEIVERS 200000
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

/* Per-receiver sender list for heartbeat construction.
 * Built once from path statuses; rebuilt only after failovers. */
typedef struct {
    uint32_t receiver_id;
    uint32_t senders[MAX_SENDERS_PER_RECV];
    int      count;
} recv_bucket;

static recv_bucket *buckets;
static int          num_buckets;

/* rid_to_bucket[rid] = index into buckets[], -1 if none.
 * Sized to max receiver_id + 1 for O(1) lookup. */
static int *rid_to_bucket;
static int  rid_to_bucket_sz;

static void rebuild_map(didaqt_ctrl_ctx *ctx)
{
    didaqt_path_info *paths;
    int path_count;
    didaqt_ctrl_get_path_statuses(ctx, &paths, &path_count);

    /* Reset. */
    num_buckets = 0;
    if (rid_to_bucket)
        memset(rid_to_bucket, 0xff, rid_to_bucket_sz * sizeof(int));

    for (int i = 0; i < path_count; i++) {
        if (paths[i].status != DIDAQT_PATH_USED) continue;

        uint32_t rid = paths[i].receiver_id;
        uint32_t sid = (uint32_t)paths[i].sender_id;

        /* Grow lookup table if needed. */
        if ((int)rid >= rid_to_bucket_sz) {
            int new_sz = (int)rid + 1;
            int *tmp = realloc(rid_to_bucket, new_sz * sizeof(int));
            if (!tmp) {
                fprintf(stderr, "rebuild_map: realloc failed\n");
                free(paths);
                return;
            }
            memset(tmp + rid_to_bucket_sz, 0xff,
                   (new_sz - rid_to_bucket_sz) * sizeof(int));
            rid_to_bucket = tmp;
            rid_to_bucket_sz = new_sz;
        }

        int b = rid_to_bucket[rid];
        if (b < 0) {
            if (num_buckets >= MAX_RECEIVERS) continue;
            b = num_buckets++;
            buckets[b].receiver_id = rid;
            buckets[b].count = 0;
            rid_to_bucket[rid] = b;
        }
        if (buckets[b].count < MAX_SENDERS_PER_RECV)
            buckets[b].senders[buckets[b].count++] = sid;
    }

    free(paths);
}

/* Send heartbeats from all receivers with their current USED senders. */
static void send_all_heartbeats(didaqt_ctrl_ctx *ctx)
{
    rebuild_map(ctx);

    uint8_t buf[6 + MAX_SENDERS_PER_RECV * 4];
    for (int i = 0; i < num_buckets; i++) {
        int len = build_hb(buckets[i].receiver_id,
                           buckets[i].senders, buckets[i].count,
                           buf, sizeof(buf));
        if (len > 0)
            didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);
    }
}

/* Find the receiver_id for a given sender (by USED path in current map). */
static uint32_t find_sender_recv(uint32_t sid)
{
    for (int i = 0; i < num_buckets; i++) {
        for (int j = 0; j < buckets[i].count; j++) {
            if (buckets[i].senders[j] == sid)
                return buckets[i].receiver_id;
        }
    }
    return 0;
}

/* Build heartbeat for a receiver, excluding one sender.
 * Uses the current map — no re-query. */
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

    /* Allocate receiver buckets. */
    buckets = calloc(MAX_RECEIVERS, sizeof(recv_bucket));
    if (!buckets) {
        fprintf(stderr, "bucket alloc failed\n");
        return 1;
    }

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
        free(buckets);
        return 1;
    }

    long preprocess_ns = (t1.tv_sec - t0.tv_sec) * 1000000000L
                        + (t1.tv_nsec - t0.tv_nsec);

    /* Register mock handler. */
    if (didaqt_ctrl_register_handler(ctx, "tofino2", mock_handler, NULL)
        != DIDAQT_OK) {
        fprintf(stderr, "register_handler failed\n");
        didaqt_ctrl_destroy(ctx);
        free(buckets);
        return 1;
    }

    /* ---- Mark all senders as "seen" ---- */
    send_all_heartbeats(ctx);
    send_all_heartbeats(ctx);

    /* ---- Run failover trials ---- */
    uint32_t target_sid = 1;  /* Always fail S1 */
    long decisions[NUM_TRIALS];

    for (int t = 0; t < NUM_TRIALS; t++) {
        /* Map is current from the previous send_all_heartbeats. */
        uint32_t rid = find_sender_recv(target_sid);
        if (rid == 0) {
            fprintf(stderr, "trial %d: sender %u has no USED path\n",
                    t, target_sid);
            decisions[t] = -1;
            continue;
        }

        /* Build heartbeat from rid WITHOUT target sender. */
        uint8_t buf[6 + MAX_SENDERS_PER_RECV * 4];
        int len = build_hb_without(rid, target_sid, buf, sizeof(buf));
        if (len < 0) {
            fprintf(stderr, "trial %d: build_hb_without failed\n", t);
            decisions[t] = -1;
            continue;
        }

        g_decision_ns = 0;
        didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);
        decisions[t] = g_decision_ns;

        /* Confirm failover: send heartbeats with current state. */
        send_all_heartbeats(ctx);
        send_all_heartbeats(ctx);
    }

    /* ---- Output results ---- */
    /* num_buckets = distinct receivers with USED paths = active receivers. */
    int active_recv = num_buckets;

    fprintf(stderr, "active_receivers=%d switches_per_path=%d preprocess=%.3fms\n",
            active_recv, switch_count, preprocess_ns / 1e6);

    /* Line 1: active_receivers, switch_count, preprocess_ns */
    printf("%d,%d,%ld\n", active_recv, switch_count, preprocess_ns);

    /* Lines 2-11: decision_ns per trial (skip failed trials) */
    for (int t = 0; t < NUM_TRIALS; t++) {
        if (decisions[t] < 0)
            printf("FAIL\n");
        else
            printf("%ld\n", decisions[t]);
    }

    didaqt_ctrl_destroy(ctx);
    free(buckets);
    free(rid_to_bucket);
    return 0;
}
