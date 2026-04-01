/*
 * bench_ctrl_extra.c — Benchmark sorting and worst-case path search
 *
 * Measures:
 *   1. compute_ordering time (the sorting step of preprocessing)
 *   2. Worst-case failover decision time: only the last path in a
 *      sender's path list is AVAILABLE, forcing first_available()
 *      to scan the entire list.
 *
 * Usage:
 *   ./bench_ctrl_extra <topology.yaml> <switch_count>
 *
 * Output (to stdout):
 *   Line 1:  active_receivers,switch_count,sort_ns,paths_per_sender
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

    /* ---- Preprocess ---- */
    if (didaqt_ctrl_process_topology(yaml_path, ctx) != DIDAQT_OK) {
        fprintf(stderr, "process_topology failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }

    long sort_ns = didaqt_ctrl_get_ordering_time(ctx);

    if (didaqt_ctrl_register_handler(ctx, "tofino2", mock_handler, NULL)
        != DIDAQT_OK) {
        fprintf(stderr, "register_handler failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }

    /* ---- Get path info for sender 1 ---- */
    didaqt_path_info *all_paths;
    int all_count;
    if (didaqt_ctrl_get_path_statuses(ctx, &all_paths, &all_count) != DIDAQT_OK) {
        fprintf(stderr, "get_path_statuses failed\n");
        didaqt_ctrl_destroy(ctx);
        return 1;
    }

    /* Collect sender 1's path IDs and the receiver for the USED path. */
    int *s1_path_ids = NULL;
    int  s1_path_count = 0;
    int  s1_used_idx = -1;       /* index into s1_path_ids of the USED path */
    uint32_t s1_used_rid = 0;

    /* Count active receivers for output. */
    int active_recv = 0;
    {
        uint32_t *seen_rids = NULL;
        int n_seen = 0;
        for (int i = 0; i < all_count; i++) {
            if (all_paths[i].status != DIDAQT_PATH_USED) continue;
            uint32_t rid = all_paths[i].receiver_id;
            int found = 0;
            for (int j = 0; j < n_seen; j++)
                if (seen_rids[j] == rid) { found = 1; break; }
            if (!found) {
                seen_rids = realloc(seen_rids, (n_seen + 1) * sizeof(uint32_t));
                seen_rids[n_seen++] = rid;
            }
        }
        active_recv = n_seen;
        free(seen_rids);
    }

    /* Gather sender 1's paths. */
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
    free(all_paths);

    if (s1_path_count < 2 || s1_used_idx < 0) {
        fprintf(stderr, "sender 1 has %d paths (need >=2), used_idx=%d\n",
                s1_path_count, s1_used_idx);
        free(s1_path_ids);
        didaqt_ctrl_destroy(ctx);
        return 1;
    }

    fprintf(stderr, "sender 1: %d paths, used_idx=%d, used_rid=%u\n",
            s1_path_count, s1_used_idx, s1_used_rid);

    /* ---- Collect all senders at the USED receiver for heartbeats ---- */
    uint32_t recv_sids[MAX_SENDERS_PER_RECV];
    int recv_sid_count = 0;
    {
        didaqt_path_info *ps;
        int pc;
        didaqt_ctrl_get_path_statuses(ctx, &ps, &pc);
        for (int i = 0; i < pc; i++) {
            if (ps[i].status == DIDAQT_PATH_USED &&
                ps[i].receiver_id == s1_used_rid &&
                recv_sid_count < MAX_SENDERS_PER_RECV)
                recv_sids[recv_sid_count++] = (uint32_t)ps[i].sender_id;
        }
        free(ps);
    }

    /* ---- Mark all senders as "seen" ---- */
    {
        /* Send heartbeats for all receivers via a full path scan. */
        didaqt_path_info *ps;
        int pc;
        didaqt_ctrl_get_path_statuses(ctx, &ps, &pc);

        /* Collect unique receiver IDs. */
        uint32_t *rids = NULL;
        int nr = 0;
        for (int i = 0; i < pc; i++) {
            if (ps[i].status != DIDAQT_PATH_USED) continue;
            uint32_t rid = ps[i].receiver_id;
            int found = 0;
            for (int j = 0; j < nr; j++)
                if (rids[j] == rid) { found = 1; break; }
            if (!found) {
                rids = realloc(rids, (nr + 1) * sizeof(uint32_t));
                rids[nr++] = rid;
            }
        }

        /* For each receiver, build and send a heartbeat with all its senders. */
        uint8_t buf[6 + MAX_SENDERS_PER_RECV * 4];
        for (int r = 0; r < nr; r++) {
            uint32_t sids[MAX_SENDERS_PER_RECV];
            int cnt = 0;
            for (int i = 0; i < pc; i++) {
                if (ps[i].status == DIDAQT_PATH_USED &&
                    ps[i].receiver_id == rids[r] &&
                    cnt < MAX_SENDERS_PER_RECV)
                    sids[cnt++] = (uint32_t)ps[i].sender_id;
            }
            int len = build_hb(rids[r], sids, cnt, buf, sizeof(buf));
            if (len > 0) didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);
        }
        /* Second round. */
        for (int r = 0; r < nr; r++) {
            uint32_t sids[MAX_SENDERS_PER_RECV];
            int cnt = 0;
            for (int i = 0; i < pc; i++) {
                if (ps[i].status == DIDAQT_PATH_USED &&
                    ps[i].receiver_id == rids[r] &&
                    cnt < MAX_SENDERS_PER_RECV)
                    sids[cnt++] = (uint32_t)ps[i].sender_id;
            }
            int len = build_hb(rids[r], sids, cnt, buf, sizeof(buf));
            if (len > 0) didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);
        }
        free(rids);
        free(ps);
    }

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

        /* Find the receiver for path 0 (the USED path). */
        didaqt_path_info *ps;
        int pc;
        didaqt_ctrl_get_path_statuses(ctx, &ps, &pc);
        uint32_t used_rid = 0;
        for (int i = 0; i < pc; i++) {
            if (ps[i].path_id == s1_path_ids[0]) {
                used_rid = ps[i].receiver_id;
                break;
            }
        }

        /* Collect all senders at this receiver. */
        uint32_t cur_sids[MAX_SENDERS_PER_RECV];
        int cur_cnt = 0;
        for (int i = 0; i < pc; i++) {
            if (ps[i].status == DIDAQT_PATH_USED &&
                ps[i].receiver_id == used_rid &&
                cur_cnt < MAX_SENDERS_PER_RECV)
                cur_sids[cur_cnt++] = (uint32_t)ps[i].sender_id;
        }
        free(ps);

        /* Prime: send heartbeat WITH sender 1 so seen/seen_at_recv are set. */
        uint8_t buf[6 + MAX_SENDERS_PER_RECV * 4];
        int len = build_hb(used_rid, cur_sids, cur_cnt, buf, sizeof(buf));
        if (len > 0) didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);

        /* Trigger failover: heartbeat WITHOUT sender 1. */
        uint32_t filtered[MAX_SENDERS_PER_RECV];
        int filt_cnt = 0;
        for (int i = 0; i < cur_cnt; i++) {
            if (cur_sids[i] != 1)
                filtered[filt_cnt++] = cur_sids[i];
        }

        g_decision_ns = 0;
        len = build_hb(used_rid, filtered, filt_cnt, buf, sizeof(buf));
        if (len > 0) didaqt_ctrl_process_heartbeat(buf, (size_t)len, ctx);
        decisions[t] = g_decision_ns;
    }

    /* ---- Output results ---- */
    fprintf(stderr, "active_receivers=%d switches=%d sort=%.3fms "
            "paths_per_sender=%d\n",
            active_recv, switch_count, sort_ns / 1e6, s1_path_count);

    printf("%d,%d,%ld,%d\n", active_recv, switch_count, sort_ns,
           s1_path_count);

    for (int t = 0; t < NUM_TRIALS; t++) {
        if (decisions[t] <= 0)
            printf("FAIL\n");
        else
            printf("%ld\n", decisions[t]);
    }

    free(s1_path_ids);
    didaqt_ctrl_destroy(ctx);
    return 0;
}
