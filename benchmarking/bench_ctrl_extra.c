/*
 * bench_ctrl_extra.c — Benchmark preprocessing and worst-case path search
 *
 * Measures:
 *   1. Full preprocessing time (topology parsing + path finding + sorting)
 *   2. Worst-case failover decision time: only the last path in a
 *      sender's path list is AVAILABLE, forcing first_available()
 *      to scan the entire list.
 *
 * Usage:
 *   ./bench_ctrl_extra <topology.yaml> <switch_count>
 *
 * Output (to stdout):
 *   Line 1:  active_receivers,switch_count,preprocess_ns,paths_per_sender
 *   Lines 2-11: worst_case_decision_ns (one per trial, 10 total)
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
/*  Event callback                                                     */
/* ------------------------------------------------------------------ */

static long g_decision_ns;

static void event_cb(const didaqt_event *ev,
                      __attribute__((unused)) void *ud)
{
    if (ev->type == DIDAQT_EVENT_FAILOVER)
        g_decision_ns = ev->elapsed_ns;
}

/* ------------------------------------------------------------------ */
/*  Mock switch handler                                                */
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
/*  Receiver→sender map (built once from initial path snapshot)        */
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

static int build_map(didaqt_ctrl_ctx *ctx)
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
    }

    free(paths);
    return 0;
}

/* Send heartbeats for all receivers from the map. */
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

/* Send heartbeat for a single receiver by rid, using the map. */
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

/* Get the senders at a receiver from the map. */
static int get_bucket_senders(uint32_t rid, uint32_t *out, int max_out)
{
    if ((int)rid >= rid_to_bucket_sz) return 0;
    int b = rid_to_bucket[rid];
    if (b < 0) return 0;
    int cnt = buckets[b].count < max_out ? buckets[b].count : max_out;
    memcpy(out, buckets[b].senders, cnt * sizeof(uint32_t));
    return cnt;
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
    if (didaqt_ctrl_process_topology(yaml_path, ctx) != DIDAQT_OK) {
        fprintf(stderr, "process_topology failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    long preprocess_ns = (t1.tv_sec - t0.tv_sec) * 1000000000L
                        + (t1.tv_nsec - t0.tv_nsec);

    if (didaqt_ctrl_register_handler(ctx, "tofino2", mock_handler, NULL)
        != DIDAQT_OK) {
        fprintf(stderr, "register_handler failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }

    /* ---- Build receiver→sender map once ---- */
    if (build_map(ctx) < 0) {
        fprintf(stderr, "build_map failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }
    int active_recv = num_buckets;

    /* ---- Get sender 1's path IDs and receiver for path 0 ---- */
    didaqt_path_info *all_paths;
    int all_count;
    if (didaqt_ctrl_get_path_statuses(ctx, &all_paths, &all_count) != DIDAQT_OK) {
        fprintf(stderr, "get_path_statuses failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }

    int *s1_path_ids = NULL;
    int  s1_path_count = 0;
    int  s1_used_idx = -1;
    uint32_t s1_used_rid = 0;

    for (int i = 0; i < all_count; i++) {
        if (all_paths[i].sender_id != 1) continue;
        s1_path_ids = realloc(s1_path_ids,
                              (s1_path_count + 1) * sizeof(int));
        s1_path_ids[s1_path_count] = all_paths[i].path_id;
        if (all_paths[i].status == DIDAQT_PATH_USED) {
            s1_used_idx = s1_path_count;
            s1_used_rid = all_paths[i].receiver_id;
        }
        s1_path_count++;
    }

    /* Also store the receiver_id for path 0 (used in every trial). */
    uint32_t path0_rid = 0;
    for (int i = 0; i < all_count; i++) {
        if (all_paths[i].path_id == s1_path_ids[0]) {
            path0_rid = all_paths[i].receiver_id;
            break;
        }
    }
    free(all_paths);

    if (s1_path_count < 2 || s1_used_idx < 0) {
        fprintf(stderr, "sender 1 has %d paths (need >=2), used_idx=%d\n",
                s1_path_count, s1_used_idx);
        free(s1_path_ids);
        didaqt_ctrl_destroy(ctx);
        return 1;
    }

    fprintf(stderr, "sender 1: %d paths, used_idx=%d, used_rid=%u, "
            "path0_rid=%u\n",
            s1_path_count, s1_used_idx, s1_used_rid, path0_rid);

    /* ---- Mark all senders as "seen" via the map ---- */
    send_all_heartbeats(ctx);
    send_all_heartbeats(ctx);

    /* ---- Run worst-case failover trials ---- */
    long decisions[NUM_TRIALS];

    for (int t = 0; t < NUM_TRIALS; t++) {
        /* Reset: revive sender 1, then set up worst-case path layout. */
        didaqt_ctrl_revive_sender(ctx, 1);

        /* Set path 0 to USED, paths 1..N-2 to FAILED, path N-1 to AVAILABLE.
         * This forces first_available() to scan the entire path list. */
        for (int i = 0; i < s1_path_count; i++) {
            if (i == 0)
                didaqt_ctrl_set_path_status(ctx, s1_path_ids[i],
                                            DIDAQT_PATH_USED);
            else if (i == s1_path_count - 1)
                didaqt_ctrl_set_path_status(ctx, s1_path_ids[i],
                                            DIDAQT_PATH_AVAILABLE);
            else
                didaqt_ctrl_set_path_status(ctx, s1_path_ids[i],
                                            DIDAQT_PATH_FAILED);
        }

        /* Get senders at path 0's receiver from the pre-built map. */
        uint32_t cur_sids[MAX_SENDERS_PER_RECV];
        int cur_cnt = get_bucket_senders(path0_rid, cur_sids, MAX_SENDERS_PER_RECV);

        /* Prime: send heartbeat WITH sender 1 so seen/seen_at_recv are set. */
        uint8_t buf[6 + MAX_SENDERS_PER_RECV * 4];
        int len = build_hb(path0_rid, cur_sids, cur_cnt, buf, sizeof(buf));
        if (len > 0) didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);

        /* Trigger failover: heartbeat WITHOUT sender 1. */
        uint32_t filtered[MAX_SENDERS_PER_RECV];
        int filt_cnt = 0;
        for (int i = 0; i < cur_cnt; i++) {
            if (cur_sids[i] != 1)
                filtered[filt_cnt++] = cur_sids[i];
        }

        g_decision_ns = 0;
        len = build_hb(path0_rid, filtered, filt_cnt, buf, sizeof(buf));
        if (len > 0) didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);
        decisions[t] = g_decision_ns;
    }

    /* ---- Output results ---- */
    fprintf(stderr, "active_receivers=%d switches=%d preprocess=%.3fms "
            "paths_per_sender=%d\n",
            active_recv, switch_count, preprocess_ns / 1e6, s1_path_count);

    printf("%d,%d,%ld,%d\n", active_recv, switch_count, preprocess_ns,
           s1_path_count);

    for (int t = 0; t < NUM_TRIALS; t++) {
        if (decisions[t] <= 0)
            printf("FAIL\n");
        else
            printf("%ld\n", decisions[t]);
    }

    free(s1_path_ids);
    free(buckets);
    free(rid_to_bucket);
    didaqt_ctrl_destroy(ctx);
    return 0;
}
