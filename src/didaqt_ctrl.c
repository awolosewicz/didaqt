#include "didaqt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <yaml.h>

/* ------------------------------------------------------------------ */
/*  Internal limits / initial sizes                                    */
/* ------------------------------------------------------------------ */

#define INIT_PATHS     64
#define INIT_HANDLERS   4
#define NAME_LEN  DIDAQT_MAX_NAME

/* ------------------------------------------------------------------ */
/*  Internal types                                                     */
/* ------------------------------------------------------------------ */

typedef enum {
    NODE_SENDER,
    NODE_RECEIVER,
    NODE_SENDER_RECEIVER,
    NODE_SWITCH,
} node_type;

typedef struct {
    char sender[NAME_LEN];
    char receiver[NAME_LEN];
} init_conn;

typedef struct {
    int       port_num;
    char      other_node[NAME_LEN];
    int       other_node_idx;           /* resolved after parse */
    int       other_port;
    uint64_t  max_bandwidth;
    init_conn *init_conns;
    int       num_init_conns;
} connection;

typedef struct {
    char      name[NAME_LEN];
    node_type type;

    /* sender attrs (SENDER, SENDER_RECEIVER) */
    uint64_t  sender_id;
    int       sender_id_bytes;
    uint64_t  max_bandwidth;
    char      initial_receiver[NAME_LEN];
    uint32_t  group_id;

    /* receiver attrs (RECEIVER, SENDER_RECEIVER) */
    uint32_t  receiver_id;

    /* switch attrs */
    char      switch_type_group[NAME_LEN];

    connection *conns;
    int        num_conns;
} topo_node;

typedef struct {
    int node_idx;
    int ingress_port;
    int egress_port;
} path_hop;

typedef struct {
    int                sender_idx;
    int                receiver_idx;
    path_hop          *hops;
    int                num_hops;
    int                contention;
    int                switch_updates;
    didaqt_path_status status;
} ctrl_path;

typedef struct {
    char                    type_group[NAME_LEN];
    didaqt_switch_handler_fn fn;
    void                   *user_data;
} ctrl_handler;

/* Per-sender runtime state, consolidated for cache locality. */
typedef struct {
    int             dead;
    int             seen;            /* ever seen in any heartbeat */
    int             seen_at_recv;    /* seen at current receiver since last failover */
    int             miss_count;      /* consecutive heartbeats missed */
    struct timespec last_failover;
    struct timespec failover_initiated_at;  /* for confirmation timing */
} sender_runtime;

/* Lookup entry for sorted sender_id/receiver_id → node_idx tables. */
typedef struct {
    uint64_t id;
    int      node_idx;
} id_lookup;

struct didaqt_ctrl_ctx {
    topo_node   *nodes;
    int          num_nodes;

    ctrl_path   *paths;
    int          num_paths;
    int          max_paths;      /* current allocation size */

    /* Per-sender path index: paths are grouped by sender after ordering.
     * sender_path_start[node_idx] = first path index for that sender.
     * sender_path_count[node_idx] = number of paths for that sender. */
    int         *sender_path_start;
    int         *sender_path_count;

    /* Per-receiver path index: recv_path_idx[] stores path indices
     * grouped by receiver.  recv_path_start/count index into it.
     * Built once during preprocessing; O(senders_at_recv) lookup. */
    int         *recv_path_idx;
    int         *recv_path_start;
    int         *recv_path_count;

    /* Post-failover grace period in nanoseconds. */
    long         grace_period_ns;

    /* Consecutive missed heartbeats required to trigger failover. */
    int          miss_threshold;

    /* Per-node runtime state (allocated to num_nodes after YAML parse). */
    sender_runtime *runtime;

    /* Pre-allocated scratch for handled_groups in process_heartbeat. */
    uint32_t    *handled_groups;

    /* Pre-allocated rollback buffer for group failover. */
    didaqt_path_status *rollback_buf;
    int                 rollback_cap;

    /* Sorted lookup tables built after YAML parse. */
    id_lookup   *sender_lookup;    /* sender_id → node_idx */
    int          num_sender_lookup;
    id_lookup   *recv_lookup;      /* receiver_id → node_idx */
    int          num_recv_lookup;

    ctrl_handler *handlers;
    int           num_handlers;
    int           max_handlers;

    /* Event callback for failover timing. */
    didaqt_event_fn event_fn;
    void           *event_user_data;
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static long timespec_diff_ns(const struct timespec *a, const struct timespec *b)
{
    return (a->tv_sec  - b->tv_sec) * 1000000000L
         + (a->tv_nsec - b->tv_nsec);
}

static void fire_event(const didaqt_ctrl_ctx *ctx, didaqt_event_type type,
                        uint64_t sender_id, uint32_t group_id, long elapsed_ns)
{
    if (!ctx->event_fn) return;
    didaqt_event ev = { .type = type, .sender_id = sender_id,
                        .group_id = group_id, .elapsed_ns = elapsed_ns };
    ctx->event_fn(&ev, ctx->event_user_data);
}

static int find_node(const didaqt_ctrl_ctx *ctx, const char *name)
{
    for (int i = 0; i < ctx->num_nodes; i++)
        if (strcmp(ctx->nodes[i].name, name) == 0)
            return i;
    return -1;
}

static int node_is_sender(const topo_node *n)
{
    return n->type == NODE_SENDER || n->type == NODE_SENDER_RECEIVER;
}

static int node_is_receiver(const topo_node *n)
{
    return n->type == NODE_RECEIVER || n->type == NODE_SENDER_RECEIVER;
}

static int node_forwards(const topo_node *n)
{
    return n->type == NODE_SWITCH || n->type == NODE_SENDER_RECEIVER;
}

static uint64_t parse_bandwidth(const char *s)
{
    if (!s) return 0;
    char *end;
    double v = strtod(s, &end);
    switch (*end) {
    case 'T': case 't': return (uint64_t)(v * 1e12);
    case 'G': case 'g': return (uint64_t)(v * 1e9);
    case 'M': case 'm': return (uint64_t)(v * 1e6);
    case 'K': case 'k': return (uint64_t)(v * 1e3);
    default:            return (uint64_t)v;
    }
}

/* ---- Sorted ID lookup helpers ---- */

static int id_lookup_cmp(const void *a, const void *b)
{
    uint64_t ia = ((const id_lookup *)a)->id;
    uint64_t ib = ((const id_lookup *)b)->id;
    return (ia > ib) - (ia < ib);
}

static int id_lookup_find(const id_lookup *tbl, int count, uint64_t id)
{
    int lo = 0, hi = count - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (tbl[mid].id == id) return tbl[mid].node_idx;
        if (tbl[mid].id < id) lo = mid + 1;
        else                  hi = mid - 1;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  YAML helpers (document API)                                        */
/* ------------------------------------------------------------------ */

static const char *scalar_val(__attribute__((unused)) yaml_document_t *doc,
                              yaml_node_t *n)
{
    if (!n || n->type != YAML_SCALAR_NODE) return NULL;
    return (const char *)n->data.scalar.value;
}

static yaml_node_t *map_get(yaml_document_t *doc, yaml_node_t *map,
                            const char *key)
{
    if (!map || map->type != YAML_MAPPING_NODE) return NULL;
    for (yaml_node_pair_t *p = map->data.mapping.pairs.start;
         p < map->data.mapping.pairs.top; p++) {
        yaml_node_t *k = yaml_document_get_node(doc, p->key);
        if (k && k->type == YAML_SCALAR_NODE &&
            strcmp((const char *)k->data.scalar.value, key) == 0)
            return yaml_document_get_node(doc, p->value);
    }
    return NULL;
}

static const char *map_str(yaml_document_t *doc, yaml_node_t *map,
                           const char *key)
{
    return scalar_val(doc, map_get(doc, map, key));
}

/* ------------------------------------------------------------------ */
/*  YAML parsing                                                       */
/* ------------------------------------------------------------------ */

static int parse_init_conns(yaml_document_t *doc, yaml_node_t *node,
                            connection *conn)
{
    if (!node || node->type != YAML_MAPPING_NODE) return 0;

    int count = (int)(node->data.mapping.pairs.top
                    - node->data.mapping.pairs.start);
    if (count <= 0) return 0;

    conn->init_conns = calloc(count, sizeof(init_conn));
    if (!conn->init_conns) return -1;

    for (yaml_node_pair_t *p = node->data.mapping.pairs.start;
         p < node->data.mapping.pairs.top; p++) {
        yaml_node_t *val = yaml_document_get_node(doc, p->value);
        const char *s = map_str(doc, val, "sender");
        const char *r = map_str(doc, val, "receiver");
        init_conn *ic = &conn->init_conns[conn->num_init_conns++];
        if (s) strncpy(ic->sender,   s, NAME_LEN - 1);
        if (r) strncpy(ic->receiver, r, NAME_LEN - 1);
    }
    return 0;
}

static int parse_connections(yaml_document_t *doc, yaml_node_t *node,
                             topo_node *tn)
{
    if (!node || node->type != YAML_MAPPING_NODE) return 0;

    int count = (int)(node->data.mapping.pairs.top
                    - node->data.mapping.pairs.start);
    if (count <= 0) return 0;

    tn->conns = calloc(count, sizeof(connection));
    if (!tn->conns) return -1;

    for (yaml_node_pair_t *p = node->data.mapping.pairs.start;
         p < node->data.mapping.pairs.top; p++) {
        yaml_node_t *key = yaml_document_get_node(doc, p->key);
        yaml_node_t *val = yaml_document_get_node(doc, p->value);
        const char *port_s = scalar_val(doc, key);
        if (!port_s) continue;

        connection *c = &tn->conns[tn->num_conns++];
        memset(c, 0, sizeof(*c));
        c->port_num = atoi(port_s);
        c->other_node_idx = -1;

        const char *on = map_str(doc, val, "other_node");
        if (on) strncpy(c->other_node, on, NAME_LEN - 1);

        const char *op = map_str(doc, val, "other_port");
        if (op) c->other_port = atoi(op);

        const char *bw = map_str(doc, val, "max_bandwidth");
        if (bw) c->max_bandwidth = parse_bandwidth(bw);

        yaml_node_t *ic = map_get(doc, val, "initial_connections");
        if (ic && parse_init_conns(doc, ic, c) < 0) return -1;
    }
    return 0;
}

static int parse_node_entry(yaml_document_t *doc, yaml_node_t *entry,
                            topo_node *tn)
{

    const char *name = map_str(doc, entry, "name");
    if (name) strncpy(tn->name, name, NAME_LEN - 1);

    const char *type = map_str(doc, entry, "type");
    if (!type) { fprintf(stderr, "node missing type\n"); return -1; }
    if      (strcmp(type, "sender")          == 0) tn->type = NODE_SENDER;
    else if (strcmp(type, "receiver")        == 0) tn->type = NODE_RECEIVER;
    else if (strcmp(type, "sender-receiver") == 0) tn->type = NODE_SENDER_RECEIVER;
    else if (strcmp(type, "switch")          == 0) tn->type = NODE_SWITCH;
    else { fprintf(stderr, "unknown type '%s'\n", type); return -1; }

    /* sender fields */
    if (node_is_sender(tn)) {
        const char *sid = map_str(doc, entry, "sender_id");
        if (sid) tn->sender_id = strtoull(sid, NULL, 0);

        const char *sib = map_str(doc, entry, "sender_id_bytes");
        if (sib) tn->sender_id_bytes = atoi(sib);

        const char *bw = map_str(doc, entry, "max_bandwidth");
        if (bw) tn->max_bandwidth = parse_bandwidth(bw);

        const char *ir = map_str(doc, entry, "initial_receiver");
        if (ir) strncpy(tn->initial_receiver, ir, NAME_LEN - 1);

        const char *gid = map_str(doc, entry, "group_id");
        if (gid) tn->group_id = (uint32_t)strtoul(gid, NULL, 0);
    }

    /* receiver fields */
    if (node_is_receiver(tn)) {
        const char *rid = map_str(doc, entry, "receiver_id");
        if (rid) tn->receiver_id = (uint32_t)strtoul(rid, NULL, 0);
    }

    /* switch fields */
    if (tn->type == NODE_SWITCH) {
        const char *stg = map_str(doc, entry, "switch_type_group");
        if (stg) strncpy(tn->switch_type_group, stg, NAME_LEN - 1);
    }

    yaml_node_t *conns = map_get(doc, entry, "connections");
    if (conns) parse_connections(doc, conns, tn);

    return 0;
}

static int parse_yaml(const char *path, didaqt_ctrl_ctx *ctx)
{
    FILE *fp = fopen(path, "r");
    if (!fp) { perror(path); return DIDAQT_ERR; }

    yaml_parser_t parser;
    yaml_document_t doc;
    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "yaml_parser_initialize failed\n");
        fclose(fp);
        return DIDAQT_ERR;
    }
    yaml_parser_set_input_file(&parser, fp);

    if (!yaml_parser_load(&parser, &doc)) {
        fprintf(stderr, "YAML parse error: %s\n", parser.problem);
        yaml_parser_delete(&parser);
        fclose(fp);
        return DIDAQT_ERR;
    }

    yaml_node_t *root = yaml_document_get_root_node(&doc);
    if (!root || root->type != YAML_SEQUENCE_NODE) {
        fprintf(stderr, "YAML root must be a sequence\n");
        yaml_document_delete(&doc);
        yaml_parser_delete(&parser);
        fclose(fp);
        return DIDAQT_ERR;
    }

    /* Count nodes and allocate. */
    int node_count = (int)(root->data.sequence.items.top
                         - root->data.sequence.items.start);
    ctx->nodes = calloc(node_count, sizeof(topo_node));
    if (!ctx->nodes) {
        yaml_document_delete(&doc);
        yaml_parser_delete(&parser);
        fclose(fp);
        return DIDAQT_ERR;
    }

    for (yaml_node_item_t *it = root->data.sequence.items.start;
         it < root->data.sequence.items.top; it++) {
        yaml_node_t *entry = yaml_document_get_node(&doc, *it);
        if (parse_node_entry(&doc, entry, &ctx->nodes[ctx->num_nodes]) == 0)
            ctx->num_nodes++;
    }

    yaml_document_delete(&doc);
    yaml_parser_delete(&parser);
    fclose(fp);
    return DIDAQT_OK;
}

/* ------------------------------------------------------------------ */
/*  Post-parse: resolve names to indices, build lookup tables          */
/* ------------------------------------------------------------------ */

/* Sorted name→index table for O(log N) lookups during resolve. */
typedef struct { const char *name; int idx; } name_entry;

static int cmp_name_entry(const void *a, const void *b)
{
    return strcmp(((const name_entry *)a)->name,
                  ((const name_entry *)b)->name);
}

static int find_node_sorted(const name_entry *tbl, int n, const char *name)
{
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int c = strcmp(tbl[mid].name, name);
        if (c == 0) return tbl[mid].idx;
        if (c < 0) lo = mid + 1;
        else        hi = mid - 1;
    }
    return -1;
}

static void resolve_node_indices(didaqt_ctrl_ctx *ctx)
{
    int N = ctx->num_nodes;

    /* Build sorted name table: O(N log N). */
    name_entry *tbl = malloc(N * sizeof(name_entry));
    if (!tbl) {
        /* Fallback to linear scan. */
        for (int i = 0; i < N; i++) {
            topo_node *n = &ctx->nodes[i];
            for (int c = 0; c < n->num_conns; c++)
                n->conns[c].other_node_idx =
                    find_node(ctx, n->conns[c].other_node);
        }
        return;
    }
    for (int i = 0; i < N; i++) {
        tbl[i].name = ctx->nodes[i].name;
        tbl[i].idx  = i;
    }
    qsort(tbl, N, sizeof(name_entry), cmp_name_entry);

    /* Resolve: O(C log N). */
    for (int i = 0; i < N; i++) {
        topo_node *n = &ctx->nodes[i];
        for (int c = 0; c < n->num_conns; c++)
            n->conns[c].other_node_idx =
                find_node_sorted(tbl, N, n->conns[c].other_node);
    }
    free(tbl);
}

static int build_lookup_tables(didaqt_ctrl_ctx *ctx)
{
    int ns = 0, nr = 0;
    for (int i = 0; i < ctx->num_nodes; i++) {
        if (node_is_sender(&ctx->nodes[i]))   ns++;
        if (node_is_receiver(&ctx->nodes[i])) nr++;
    }

    ctx->sender_lookup = malloc(ns * sizeof(id_lookup));
    ctx->recv_lookup   = malloc(nr * sizeof(id_lookup));
    if ((!ctx->sender_lookup && ns) || (!ctx->recv_lookup && nr))
        return DIDAQT_ERR;

    ns = nr = 0;
    for (int i = 0; i < ctx->num_nodes; i++) {
        if (node_is_sender(&ctx->nodes[i])) {
            ctx->sender_lookup[ns].id       = ctx->nodes[i].sender_id;
            ctx->sender_lookup[ns].node_idx = i;
            ns++;
        }
        if (node_is_receiver(&ctx->nodes[i])) {
            ctx->recv_lookup[nr].id       = ctx->nodes[i].receiver_id;
            ctx->recv_lookup[nr].node_idx = i;
            nr++;
        }
    }
    ctx->num_sender_lookup = ns;
    ctx->num_recv_lookup   = nr;

    qsort(ctx->sender_lookup, ns, sizeof(id_lookup), id_lookup_cmp);
    qsort(ctx->recv_lookup,   nr, sizeof(id_lookup), id_lookup_cmp);
    return DIDAQT_OK;
}

/* ------------------------------------------------------------------ */
/*  Validation                                                         */
/* ------------------------------------------------------------------ */

static int validate(didaqt_ctrl_ctx *ctx)
{
    int err = 0;

    /* Unique sender_ids. */
    for (int i = 0; i < ctx->num_nodes; i++) {
        if (!node_is_sender(&ctx->nodes[i])) continue;
        for (int j = i + 1; j < ctx->num_nodes; j++) {
            if (!node_is_sender(&ctx->nodes[j])) continue;
            if (ctx->nodes[i].sender_id == ctx->nodes[j].sender_id) {
                fprintf(stderr, "duplicate sender_id %lu: '%s' and '%s'\n",
                        (unsigned long)ctx->nodes[i].sender_id,
                        ctx->nodes[i].name, ctx->nodes[j].name);
                err = 1;
            }
        }
    }

    /* Group constraint: same group_id ⇒ same initial_receiver. */
    for (int i = 0; i < ctx->num_nodes; i++) {
        if (!node_is_sender(&ctx->nodes[i])) continue;
        if (ctx->nodes[i].group_id == 0) continue;
        for (int j = i + 1; j < ctx->num_nodes; j++) {
            if (!node_is_sender(&ctx->nodes[j])) continue;
            if (ctx->nodes[i].group_id != ctx->nodes[j].group_id) continue;
            if (strcmp(ctx->nodes[i].initial_receiver,
                       ctx->nodes[j].initial_receiver) != 0) {
                fprintf(stderr,
                        "group %u: '%s' initial_receiver='%s' != "
                        "'%s' initial_receiver='%s'\n",
                        ctx->nodes[i].group_id,
                        ctx->nodes[i].name, ctx->nodes[i].initial_receiver,
                        ctx->nodes[j].name, ctx->nodes[j].initial_receiver);
                err = 1;
            }
        }
    }

    /* Bandwidth symmetry (uses resolved indices). */
    for (int i = 0; i < ctx->num_nodes; i++) {
        for (int c = 0; c < ctx->nodes[i].num_conns; c++) {
            connection *ca = &ctx->nodes[i].conns[c];
            int j = ca->other_node_idx;
            if (j < 0) {
                fprintf(stderr, "'%s' connection references unknown node '%s'\n",
                        ctx->nodes[i].name, ca->other_node);
                err = 1;
                continue;
            }
            for (int c2 = 0; c2 < ctx->nodes[j].num_conns; c2++) {
                connection *cb = &ctx->nodes[j].conns[c2];
                if (cb->other_port == ca->port_num &&
                    cb->other_node_idx == i) {
                    if (ca->max_bandwidth != cb->max_bandwidth) {
                        fprintf(stderr,
                                "bandwidth mismatch: '%s' port %d (%lu) "
                                "!= '%s' port %d (%lu)\n",
                                ctx->nodes[i].name, ca->port_num,
                                (unsigned long)ca->max_bandwidth,
                                ctx->nodes[j].name, cb->port_num,
                                (unsigned long)cb->max_bandwidth);
                        err = 1;
                    }
                }
            }
        }
    }

    return err ? DIDAQT_ERR : DIDAQT_OK;
}

/* ------------------------------------------------------------------ */
/*  Path finding (DFS)                                                 */
/* ------------------------------------------------------------------ */

/* Ensure the paths array has room for at least one more entry.
 * Doubles the allocation when full. */
static int ensure_path_capacity(didaqt_ctrl_ctx *ctx)
{
    if (ctx->num_paths < ctx->max_paths)
        return 0;

    int new_max = ctx->max_paths * 2;
    if (new_max < INIT_PATHS) new_max = INIT_PATHS;
    ctrl_path *tmp = realloc(ctx->paths, new_max * sizeof(ctrl_path));
    if (!tmp) return -1;
    memset(tmp + ctx->max_paths, 0,
           (new_max - ctx->max_paths) * sizeof(ctrl_path));
    ctx->paths     = tmp;
    ctx->max_paths = new_max;
    return 0;
}

static void dfs(didaqt_ctrl_ctx *ctx, int sender_idx,
                int cur_node, int arrived_port,
                int *visited, path_hop *hops, int max_hops, int num_hops)
{
    topo_node *n = &ctx->nodes[cur_node];

    /* If this node is a receiver endpoint, record the path. */
    if (node_is_receiver(n) && cur_node != sender_idx) {
        if (ensure_path_capacity(ctx) == 0) {
            path_hop *h = NULL;
            if (num_hops > 0) {
                h = malloc(num_hops * sizeof(path_hop));
                if (!h) return;
                memcpy(h, hops, num_hops * sizeof(path_hop));
            }
            ctrl_path *p = &ctx->paths[ctx->num_paths];
            p->sender_idx   = sender_idx;
            p->receiver_idx = cur_node;
            p->num_hops     = num_hops;
            p->hops         = h;
            p->status = DIDAQT_PATH_AVAILABLE;
            ctx->num_paths++;
        }
    }

    /* If this node can forward traffic, continue the search. */
    if (node_forwards(n)) {
        for (int c = 0; c < n->num_conns; c++) {
            connection *conn = &n->conns[c];
            if (conn->port_num == arrived_port) continue;

            int next = conn->other_node_idx;
            if (next < 0 || visited[next]) continue;
            if (num_hops >= max_hops) continue;

            hops[num_hops].node_idx     = cur_node;
            hops[num_hops].ingress_port = arrived_port;
            hops[num_hops].egress_port  = conn->port_num;

            visited[next] = 1;
            dfs(ctx, sender_idx, next, conn->other_port,
                visited, hops, max_hops, num_hops + 1);
            visited[next] = 0;
        }
    }
}

static int find_all_paths(didaqt_ctrl_ctx *ctx)
{
    int *visited = calloc(ctx->num_nodes, sizeof(int));
    if (!visited) return DIDAQT_ERR;

    /* DFS depth is bounded by the number of nodes (visited check). */
    path_hop *hops = malloc(ctx->num_nodes * sizeof(path_hop));
    if (!hops) { free(visited); return DIDAQT_ERR; }

    for (int s = 0; s < ctx->num_nodes; s++) {
        if (!node_is_sender(&ctx->nodes[s])) continue;

        for (int c = 0; c < ctx->nodes[s].num_conns; c++) {
            connection *conn = &ctx->nodes[s].conns[c];
            int next = conn->other_node_idx;
            if (next < 0) continue;

            memset(visited, 0, ctx->num_nodes * sizeof(int));
            visited[s]    = 1;
            visited[next] = 1;

            dfs(ctx, s, next, conn->other_port,
                visited, hops, ctx->num_nodes, 0);
        }
    }

    free(hops);
    free(visited);
    return DIDAQT_OK;
}

/* ------------------------------------------------------------------ */
/*  Path ordering                                                      */
/* ------------------------------------------------------------------ */

static int compute_ordering(didaqt_ctrl_ctx *ctx)
{
    int P = ctx->num_paths;
    int N = ctx->num_nodes;

    /* ---- Contention: O(P + N) ----
     * Group paths by receiver via counting sort on indices (not structs).
     * Then count distinct senders per receiver group. */

    int *recv_count  = calloc(N, sizeof(int));
    int *recv_offset = calloc(N, sizeof(int));
    int *recv_idx    = malloc(P * sizeof(int));  /* path indices by receiver */
    int *seen        = calloc(N, sizeof(int));
    int *recv_sender_count = calloc(N, sizeof(int));
    if (!recv_count || !recv_offset || !recv_idx || !seen ||
        !recv_sender_count) {
        free(recv_count); free(recv_offset); free(recv_idx);
        free(seen); free(recv_sender_count);
        return DIDAQT_ERR;
    }

    for (int i = 0; i < P; i++)
        recv_count[ctx->paths[i].receiver_idx]++;

    int off = 0;
    for (int r = 0; r < N; r++) {
        recv_offset[r] = off;
        off += recv_count[r];
    }

    /* Distribute path indices into receiver groups. */
    int *rpos = calloc(N, sizeof(int));
    if (!rpos) {
        free(recv_count); free(recv_offset); free(recv_idx);
        free(seen); free(recv_sender_count);
        return DIDAQT_ERR;
    }
    for (int i = 0; i < P; i++) {
        int r = ctx->paths[i].receiver_idx;
        recv_idx[recv_offset[r] + rpos[r]] = i;
        rpos[r]++;
    }
    free(rpos);

    /* Count distinct senders per receiver. */
    for (int r = 0; r < N; r++) {
        if (recv_count[r] == 0) continue;
        int base = recv_offset[r];
        int cnt = 0;
        for (int j = 0; j < recv_count[r]; j++) {
            int si = ctx->paths[recv_idx[base + j]].sender_idx;
            if (!seen[si]) { seen[si] = 1; cnt++; }
        }
        recv_sender_count[r] = cnt;
        /* Clear seen flags. */
        for (int j = 0; j < recv_count[r]; j++)
            seen[ctx->paths[recv_idx[base + j]].sender_idx] = 0;
    }
    free(recv_idx);
    free(recv_count);
    free(recv_offset);
    free(seen);

    for (int i = 0; i < P; i++) {
        ctx->paths[i].switch_updates = ctx->paths[i].num_hops;
        ctx->paths[i].contention =
            recv_sender_count[ctx->paths[i].receiver_idx] - 1;
    }
    free(recv_sender_count);

    /* ---- Sort paths per sender: contention asc, switch_updates asc ----
     * First sort ALL paths by sender_idx to group them, then insertion-sort
     * within each group.  Avoids the O(S*P) gather scan. */

    /* Counting sort by sender_idx → O(P + N). */
    int *count = calloc(N, sizeof(int));
    if (!count) return DIDAQT_ERR;
    for (int i = 0; i < P; i++)
        count[ctx->paths[i].sender_idx]++;

    int *offset = calloc(N, sizeof(int));
    ctrl_path *tmp = malloc(P * sizeof(ctrl_path));
    if (!offset || !tmp) {
        free(count); free(offset); free(tmp);
        return DIDAQT_ERR;
    }
    /* Prefix sum for sender offsets. */
    offset[0] = 0;
    for (int i = 1; i < N; i++)
        offset[i] = offset[i - 1] + count[i - 1];

    /* Distribute into tmp. */
    int *pos = calloc(N, sizeof(int));
    if (!pos) {
        free(count); free(offset); free(tmp);
        return DIDAQT_ERR;
    }
    for (int i = 0; i < P; i++) {
        int s = ctx->paths[i].sender_idx;
        tmp[offset[s] + pos[s]] = ctx->paths[i];
        pos[s]++;
    }
    memcpy(ctx->paths, tmp, P * sizeof(ctrl_path));
    free(tmp);
    free(pos);

    /* Insertion sort within each sender group. */
    for (int s = 0; s < N; s++) {
        if (count[s] <= 1) continue;
        int base = offset[s];
        int cnt  = count[s];
        for (int a = 1; a < cnt; a++) {
            ctrl_path key = ctx->paths[base + a];
            int b = a - 1;
            while (b >= 0) {
                ctrl_path *bp = &ctx->paths[base + b];
                if (bp->contention < key.contention) break;
                if (bp->contention == key.contention &&
                    bp->switch_updates <= key.switch_updates) break;
                ctx->paths[base + b + 1] = *bp;
                b--;
            }
            ctx->paths[base + b + 1] = key;
        }
    }
    free(count);
    free(offset);
    return DIDAQT_OK;
}

/* Build per-sender path index after paths are sorted.
 * Paths are grouped by sender, so we record start/count. */
static int build_sender_path_index(didaqt_ctrl_ctx *ctx)
{
    ctx->sender_path_start = calloc(ctx->num_nodes, sizeof(int));
    ctx->sender_path_count = calloc(ctx->num_nodes, sizeof(int));
    if (!ctx->sender_path_start || !ctx->sender_path_count)
        return DIDAQT_ERR;

    /* Paths are sorted by sender within each sender group, but
     * senders may be interleaved.  Do a single pass to count. */
    for (int i = 0; i < ctx->num_paths; i++)
        ctx->sender_path_count[ctx->paths[i].sender_idx]++;

    /* Set start indices. */
    int *pos = calloc(ctx->num_nodes, sizeof(int));
    if (!pos) return DIDAQT_ERR;
    int offset = 0;
    for (int s = 0; s < ctx->num_nodes; s++) {
        ctx->sender_path_start[s] = offset;
        pos[s] = offset;
        offset += ctx->sender_path_count[s];
    }

    /* Reorder paths to be contiguous per sender while preserving
     * the within-sender sort order. */
    ctrl_path *sorted = malloc(ctx->num_paths * sizeof(ctrl_path));
    if (!sorted) { free(pos); return DIDAQT_ERR; }
    for (int i = 0; i < ctx->num_paths; i++) {
        int s = ctx->paths[i].sender_idx;
        sorted[pos[s]++] = ctx->paths[i];
    }
    memcpy(ctx->paths, sorted, ctx->num_paths * sizeof(ctrl_path));
    free(sorted);
    free(pos);

    return DIDAQT_OK;
}

/* Build a per-receiver path index: an indirect array of path indices
 * grouped by receiver_idx, with start/count per receiver node.
 * This allows process_heartbeat to iterate only over paths relevant
 * to the heartbeat's receiver in O(paths_at_recv) instead of O(P). */
static int build_recv_path_index(didaqt_ctrl_ctx *ctx)
{
    int P = ctx->num_paths;
    int N = ctx->num_nodes;

    ctx->recv_path_count = calloc(N, sizeof(int));
    ctx->recv_path_start = calloc(N, sizeof(int));
    ctx->recv_path_idx   = malloc(P * sizeof(int));
    if (!ctx->recv_path_count || !ctx->recv_path_start || !ctx->recv_path_idx) {
        free(ctx->recv_path_count); ctx->recv_path_count = NULL;
        free(ctx->recv_path_start); ctx->recv_path_start = NULL;
        free(ctx->recv_path_idx);   ctx->recv_path_idx   = NULL;
        return DIDAQT_ERR;
    }

    /* Count paths per receiver. */
    for (int i = 0; i < P; i++)
        ctx->recv_path_count[ctx->paths[i].receiver_idx]++;

    /* Prefix sum for start offsets. */
    int offset = 0;
    for (int r = 0; r < N; r++) {
        ctx->recv_path_start[r] = offset;
        offset += ctx->recv_path_count[r];
    }

    /* Fill the indirect index. */
    int *pos = calloc(N, sizeof(int));
    if (!pos) return DIDAQT_ERR;
    for (int i = 0; i < P; i++) {
        int r = ctx->paths[i].receiver_idx;
        ctx->recv_path_idx[ctx->recv_path_start[r] + pos[r]] = i;
        pos[r]++;
    }
    free(pos);

    return DIDAQT_OK;
}

/* ------------------------------------------------------------------ */
/*  Initial state                                                      */
/* ------------------------------------------------------------------ */

/*
 * For each sender, find the path to initial_receiver that follows the
 * connections marked with matching initial_connections, and mark it
 * Used.  All other paths for that sender remain Available.
 */
static void setup_initial_state(didaqt_ctrl_ctx *ctx)
{
    for (int s = 0; s < ctx->num_nodes; s++) {
        if (!node_is_sender(&ctx->nodes[s])) continue;

        int target = find_node(ctx, ctx->nodes[s].initial_receiver);
        if (target < 0) {
            fprintf(stderr, "'%s': initial_receiver '%s' not found\n",
                    ctx->nodes[s].name, ctx->nodes[s].initial_receiver);
            continue;
        }

        int start = ctx->sender_path_start[s];
        int count = ctx->sender_path_count[s];
        for (int i = start; i < start + count; i++) {
            if (ctx->paths[i].receiver_idx == target) {
                ctx->paths[i].status = DIDAQT_PATH_USED;
                break;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Runtime — failover helpers                                         */
/* ------------------------------------------------------------------ */

static ctrl_handler *find_handler(didaqt_ctrl_ctx *ctx, const char *tg)
{
    for (int i = 0; i < ctx->num_handlers; i++)
        if (strcmp(ctx->handlers[i].type_group, tg) == 0)
            return &ctx->handlers[i];
    return NULL;
}

/*
 * Execute switch updates for transitioning from old_path to new_path.
 * Either may be NULL (pure tear-down or pure setup).
 */
static int execute_failover(didaqt_ctrl_ctx *ctx,
                            uint64_t sender_id,
                            const ctrl_path *old_p,
                            const ctrl_path *new_p)
{
    /* Collect all switch nodes involved. */
    int max_sw = (old_p ? old_p->num_hops : 0)
               + (new_p ? new_p->num_hops : 0);
    if (max_sw == 0) return 0;
    int *sw_nodes = malloc(max_sw * sizeof(int));
    if (!sw_nodes) return -1;
    int sw_count = 0;

    if (old_p) {
        for (int i = 0; i < old_p->num_hops; i++) {
            int nidx = old_p->hops[i].node_idx;
            int dup = 0;
            for (int j = 0; j < sw_count; j++)
                if (sw_nodes[j] == nidx) { dup = 1; break; }
            if (!dup) sw_nodes[sw_count++] = nidx;
        }
    }
    if (new_p) {
        for (int i = 0; i < new_p->num_hops; i++) {
            int nidx = new_p->hops[i].node_idx;
            int dup = 0;
            for (int j = 0; j < sw_count; j++)
                if (sw_nodes[j] == nidx) { dup = 1; break; }
            if (!dup) sw_nodes[sw_count++] = nidx;
        }
    }

    for (int s = 0; s < sw_count; s++) {
        int nidx = sw_nodes[s];
        topo_node *sw = &ctx->nodes[nidx];

        int cur_in = -1, cur_out = -1;
        int new_in = -1, new_out = -1;

        if (old_p) {
            for (int i = 0; i < old_p->num_hops; i++) {
                if (old_p->hops[i].node_idx == nidx) {
                    cur_in  = old_p->hops[i].ingress_port;
                    cur_out = old_p->hops[i].egress_port;
                    break;
                }
            }
        }
        if (new_p) {
            for (int i = 0; i < new_p->num_hops; i++) {
                if (new_p->hops[i].node_idx == nidx) {
                    new_in  = new_p->hops[i].ingress_port;
                    new_out = new_p->hops[i].egress_port;
                    break;
                }
            }
        }

        /* Skip if nothing changed on this switch. */
        if (cur_in == new_in && cur_out == new_out)
            continue;

        const char *tg = sw->switch_type_group;
        ctrl_handler *h = find_handler(ctx, tg);
        if (h && h->fn) {
            int rc = h->fn(sender_id, cur_in, cur_out, new_in, new_out,
                           h->user_data);
            if (rc != 0) { free(sw_nodes); return rc; }
        }
    }
    free(sw_nodes);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Runtime — heartbeat processing                                     */
/* ------------------------------------------------------------------ */

/* Find the first Available path for a sender using the path index. */
static int first_available(const didaqt_ctrl_ctx *ctx, int sender_idx)
{
    int start = ctx->sender_path_start[sender_idx];
    int count = ctx->sender_path_count[sender_idx];
    for (int i = start; i < start + count; i++)
        if (ctx->paths[i].status == DIDAQT_PATH_AVAILABLE)
            return i;
    return -1;
}

/* Move all TempFailed for a sender to Failed (confirmed dead). */
static void confirm_failed(didaqt_ctrl_ctx *ctx, int sender_idx)
{
    int start = ctx->sender_path_start[sender_idx];
    int count = ctx->sender_path_count[sender_idx];
    for (int i = start; i < start + count; i++)
        if (ctx->paths[i].status == DIDAQT_PATH_TEMP_FAILED)
            ctx->paths[i].status = DIDAQT_PATH_FAILED;
}

/* Record a failover timestamp for a sender (starts the grace period). */
static void mark_failover_time(didaqt_ctrl_ctx *ctx, int sender_idx,
                                const struct timespec *now)
{
    ctx->runtime[sender_idx].last_failover = *now;
}

/* Check if a sender is within the post-failover grace period. */
static int in_grace_period(const didaqt_ctrl_ctx *ctx, int sender_idx,
                           const struct timespec *now)
{
    const struct timespec *lf = &ctx->runtime[sender_idx].last_failover;
    long elapsed_ns = (now->tv_sec  - lf->tv_sec) * 1000000000L
                    + (now->tv_nsec - lf->tv_nsec);
    return elapsed_ns < ctx->grace_period_ns;
}

/* Reset per-sender state after a successful failover. */
static void reset_sender_after_failover(didaqt_ctrl_ctx *ctx,
                                        int sender_idx,
                                        const struct timespec *now)
{
    mark_failover_time(ctx, sender_idx, now);
    ctx->runtime[sender_idx].seen_at_recv = 0;
    ctx->runtime[sender_idx].miss_count = 0;
}

/* Recycle Failed paths back to Available for a sender.
 * TempFailed paths are NOT recycled — if every failover attempt
 * for a sender fails (all paths go TempFailed), the sender must
 * be assumed dead. */
static void recycle_failed(didaqt_ctrl_ctx *ctx, int sender_idx)
{
    int start = ctx->sender_path_start[sender_idx];
    int count = ctx->sender_path_count[sender_idx];
    for (int i = start; i < start + count; i++)
        if (ctx->paths[i].status == DIDAQT_PATH_FAILED)
            ctx->paths[i].status = DIDAQT_PATH_AVAILABLE;
}

/* Perform failover for a single (ungrouped) sender. */
static void failover_sender(didaqt_ctrl_ctx *ctx, int sender_idx,
                            int old_path_idx, const struct timespec *now)
{
    ctrl_path *old = &ctx->paths[old_path_idx];
    uint64_t sid = ctx->nodes[sender_idx].sender_id;

    old->status = DIDAQT_PATH_TEMP_FAILED;

    int new_idx = first_available(ctx, sender_idx);
    if (new_idx < 0) {
        /* No Available paths — recycle Failed (not TempFailed) and retry. */
        recycle_failed(ctx, sender_idx);
        new_idx = first_available(ctx, sender_idx);
    }

    if (new_idx >= 0) {
        ctx->paths[new_idx].status = DIDAQT_PATH_USED;

        /* Measure decision time: HB arrival to just before switch update. */
        struct timespec t_pre;
        clock_gettime(CLOCK_MONOTONIC, &t_pre);
        long decision_ns = timespec_diff_ns(&t_pre, now);

        fire_event(ctx, DIDAQT_EVENT_FAILOVER, sid,
                   ctx->nodes[sender_idx].group_id, decision_ns);

        if (execute_failover(ctx, sid, old, &ctx->paths[new_idx]) != 0) {
            /* Switch update failed — rollback path state. */
            old->status = DIDAQT_PATH_USED;
            ctx->paths[new_idx].status = DIDAQT_PATH_AVAILABLE;
            fprintf(stderr, "sender '%s' (id %lu): switch update failed, "
                    "rollback\n",
                    ctx->nodes[sender_idx].name, (unsigned long)sid);
            return;
        }

        /* Record time after switch update for confirmation measurement. */
        clock_gettime(CLOCK_MONOTONIC,
                      &ctx->runtime[sender_idx].failover_initiated_at);
        reset_sender_after_failover(ctx, sender_idx, now);
    } else {
        /* Still nothing — all paths are TempFailed, sender is dead. */
        ctx->runtime[sender_idx].dead = 1;
        fire_event(ctx, DIDAQT_EVENT_DEAD, sid,
                   ctx->nodes[sender_idx].group_id, 0);
        fprintf(stderr, "sender '%s' (id %lu): all paths exhausted, "
                "sender marked dead\n",
                ctx->nodes[sender_idx].name, (unsigned long)sid);
    }
}

/*
 * Failover all senders in the same group together.
 *
 * All senders in a group share the same receiver, so this:
 *   1. Picks a representative sender to determine old/new paths
 *   2. Moves ALL group members' path state atomically
 *   3. Executes ONE switch update (they share the forwarding entry)
 */
static void failover_group(didaqt_ctrl_ctx *ctx, uint32_t group_id,
                           const struct timespec *now)
{
    /* Find a representative sender (must be alive) and its current Used path. */
    int rep = -1, rep_old = -1;
    for (int s = 0; s < ctx->num_nodes && rep < 0; s++) {
        if (!node_is_sender(&ctx->nodes[s])) continue;
        if (ctx->nodes[s].group_id != group_id) continue;
        if (ctx->runtime[s].dead) continue;
        int start = ctx->sender_path_start[s];
        int count = ctx->sender_path_count[s];
        for (int i = start; i < start + count; i++) {
            if (ctx->paths[i].status == DIDAQT_PATH_USED) {
                rep = s;
                rep_old = i;
                break;
            }
        }
    }
    if (rep < 0) return;

    /* Find the new receiver via the representative's Available paths. */
    int rep_new = first_available(ctx, rep);
    if (rep_new < 0) {
        /* No Available — recycle Failed (not TempFailed) for the
         * entire group and retry. */
        for (int s = 0; s < ctx->num_nodes; s++) {
            if (!node_is_sender(&ctx->nodes[s])) continue;
            if (ctx->nodes[s].group_id != group_id) continue;
            recycle_failed(ctx, s);
        }
        rep_new = first_available(ctx, rep);
    }
    if (rep_new < 0) {
        /* Still nothing — all paths are TempFailed, group is dead. */
        for (int s = 0; s < ctx->num_nodes; s++) {
            if (!node_is_sender(&ctx->nodes[s])) continue;
            if (ctx->nodes[s].group_id != group_id) continue;
            ctx->runtime[s].dead = 1;
        }
        fire_event(ctx, DIDAQT_EVENT_DEAD, 0, group_id, 0);
        fprintf(stderr, "group %u: all paths exhausted\n", group_id);
        return;
    }

    int new_receiver = ctx->paths[rep_new].receiver_idx;

    /* Snapshot path statuses for rollback using pre-allocated buffer. */
    if (ctx->num_paths > ctx->rollback_cap) {
        didaqt_path_status *tmp = realloc(ctx->rollback_buf,
                                          ctx->num_paths * sizeof(didaqt_path_status));
        if (!tmp) {
            fprintf(stderr, "group %u: rollback alloc failed, "
                    "failover skipped\n", group_id);
            return;
        }
        ctx->rollback_buf = tmp;
        ctx->rollback_cap = ctx->num_paths;
    }
    for (int i = 0; i < ctx->num_paths; i++)
        ctx->rollback_buf[i] = ctx->paths[i].status;

    /* Move alive senders in the group: Used→TempFailed, new path→Used. */
    for (int s = 0; s < ctx->num_nodes; s++) {
        if (!node_is_sender(&ctx->nodes[s])) continue;
        if (ctx->nodes[s].group_id != group_id) continue;
        if (ctx->runtime[s].dead) continue;

        int start = ctx->sender_path_start[s];
        int count = ctx->sender_path_count[s];

        /* TempFail the current Used path. */
        for (int i = start; i < start + count; i++) {
            if (ctx->paths[i].status == DIDAQT_PATH_USED) {
                ctx->paths[i].status = DIDAQT_PATH_TEMP_FAILED;
                break;
            }
        }

        /* Activate the path to the new receiver. */
        for (int i = start; i < start + count; i++) {
            if (ctx->paths[i].receiver_idx == new_receiver) {
                ctx->paths[i].status = DIDAQT_PATH_USED;
                break;
            }
        }

        reset_sender_after_failover(ctx, s, now);
    }

    /* ONE switch update using the representative's old/new paths. */
    struct timespec t_pre;
    clock_gettime(CLOCK_MONOTONIC, &t_pre);
    long decision_ns = timespec_diff_ns(&t_pre, now);

    fire_event(ctx, DIDAQT_EVENT_FAILOVER,
               ctx->nodes[rep].sender_id, group_id, decision_ns);

    if (execute_failover(ctx, ctx->nodes[rep].sender_id,
                         &ctx->paths[rep_old], &ctx->paths[rep_new]) != 0) {
        /* Switch update failed — rollback ALL path statuses. */
        for (int i = 0; i < ctx->num_paths; i++)
            ctx->paths[i].status = ctx->rollback_buf[i];
        fprintf(stderr, "group %u: switch update failed, rollback\n",
                group_id);
        return;
    }

    /* Record time after switch update for confirmation measurement. */
    struct timespec t_post;
    clock_gettime(CLOCK_MONOTONIC, &t_post);
    for (int s = 0; s < ctx->num_nodes; s++) {
        if (!node_is_sender(&ctx->nodes[s])) continue;
        if (ctx->nodes[s].group_id != group_id) continue;
        if (!ctx->runtime[s].dead)
            ctx->runtime[s].failover_initiated_at = t_post;
    }
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

int didaqt_ctrl_init_ctx(didaqt_ctrl_ctx **ctx)
{
    if (!ctx) return DIDAQT_ERR;
    didaqt_ctrl_ctx *c = calloc(1, sizeof(*c));
    if (!c) return DIDAQT_ERR;

    c->grace_period_ns = DIDAQT_DEFAULT_GRACE_PERIOD_NS;
    c->miss_threshold  = DIDAQT_DEFAULT_MISS_THRESHOLD;

    *ctx = c;
    return DIDAQT_OK;
}

int didaqt_ctrl_set_grace_period(didaqt_ctrl_ctx *ctx, long grace_ns)
{
    if (!ctx || grace_ns < 0) return DIDAQT_ERR;
    ctx->grace_period_ns = grace_ns;
    return DIDAQT_OK;
}

int didaqt_ctrl_set_miss_threshold(didaqt_ctrl_ctx *ctx, int threshold)
{
    if (!ctx || threshold < 1) return DIDAQT_ERR;
    ctx->miss_threshold = threshold;
    return DIDAQT_OK;
}

int didaqt_ctrl_set_event_callback(didaqt_ctrl_ctx *ctx,
                                    didaqt_event_fn fn, void *user_data)
{
    if (!ctx) return DIDAQT_ERR;
    ctx->event_fn        = fn;
    ctx->event_user_data = user_data;
    return DIDAQT_OK;
}

/* Allocate per-node runtime arrays after YAML parse. */
static int alloc_node_arrays(didaqt_ctrl_ctx *ctx)
{
    int n = ctx->num_nodes;
    ctx->runtime = calloc(n, sizeof(sender_runtime));
    ctx->handled_groups = calloc(n, sizeof(uint32_t));
    if (!ctx->runtime || !ctx->handled_groups) {
        free(ctx->runtime);        ctx->runtime = NULL;
        free(ctx->handled_groups);  ctx->handled_groups = NULL;
        return DIDAQT_ERR;
    }
    return DIDAQT_OK;
}

int didaqt_ctrl_process_topology(const char *yaml_path,
                                 didaqt_ctrl_ctx *ctx)
{
    if (!ctx || !yaml_path) return DIDAQT_ERR;

    int rc = parse_yaml(yaml_path, ctx);
    if (rc != DIDAQT_OK) return rc;

    resolve_node_indices(ctx);

    rc = build_lookup_tables(ctx);
    if (rc != DIDAQT_OK) return rc;

    rc = alloc_node_arrays(ctx);
    if (rc != DIDAQT_OK) return rc;

    rc = validate(ctx);
    if (rc != DIDAQT_OK) return rc;

    rc = find_all_paths(ctx);
    if (rc != DIDAQT_OK) return rc;

    rc = compute_ordering(ctx);
    if (rc != DIDAQT_OK) return rc;

    rc = build_sender_path_index(ctx);
    if (rc != DIDAQT_OK) return rc;

    rc = build_recv_path_index(ctx);
    if (rc != DIDAQT_OK) return rc;

    setup_initial_state(ctx);

    return DIDAQT_OK;
}

int didaqt_ctrl_register_handler(didaqt_ctrl_ctx *ctx,
                                 const char *switch_type_group,
                                 didaqt_switch_handler_fn fn,
                                 void *user_data)
{
    if (!ctx || !switch_type_group || !fn) return DIDAQT_ERR;

    /* Grow handlers array if needed. */
    if (ctx->num_handlers >= ctx->max_handlers) {
        int new_max = ctx->max_handlers ? ctx->max_handlers * 2 : INIT_HANDLERS;
        ctrl_handler *tmp = realloc(ctx->handlers,
                                    new_max * sizeof(ctrl_handler));
        if (!tmp) return DIDAQT_ERR;
        memset(tmp + ctx->max_handlers, 0,
               (new_max - ctx->max_handlers) * sizeof(ctrl_handler));
        ctx->handlers     = tmp;
        ctx->max_handlers = new_max;
    }

    ctrl_handler *h = &ctx->handlers[ctx->num_handlers++];
    strncpy(h->type_group, switch_type_group, NAME_LEN - 1);
    h->fn        = fn;
    h->user_data = user_data;
    return DIDAQT_OK;
}

int didaqt_ctrl_process_heartbeat(const uint8_t *buf, size_t len,
                                  didaqt_ctrl_ctx *ctx)
{
    if (!ctx || !buf || len < 6) return DIDAQT_ERR;

    /* Single clock_gettime for the entire heartbeat processing. */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Parse heartbeat wire format. */
    uint32_t rid;
    uint16_t scnt;
    memcpy(&rid,  buf,     4); rid  = ntohl(rid);
    memcpy(&scnt, buf + 4, 2); scnt = ntohs(scnt);

    if (len < 6 + (size_t)scnt * 4) return DIDAQT_ERR;

    uint32_t sids[DIDAQT_MAX_SENDERS];
    for (int i = 0; i < scnt; i++) {
        memcpy(&sids[i], buf + 6 + i * 4, 4);
        sids[i] = ntohl(sids[i]);
    }

    /* Linear scan over sids[] to check sender presence.
     * Acceptable since scnt <= DIDAQT_MAX_SENDERS (256). */

    int recv_idx = id_lookup_find(ctx->recv_lookup, ctx->num_recv_lookup, rid);
    if (recv_idx < 0) return DIDAQT_ERR;

    /* Auto-revive dead senders that reappear in this heartbeat. */
    for (int si = 0; si < scnt; si++) {
        int s = id_lookup_find(ctx->sender_lookup, ctx->num_sender_lookup,
                               sids[si]);
        if (s < 0 || !ctx->runtime[s].dead) continue;

        didaqt_ctrl_revive_sender(ctx, (uint64_t)sids[si]);
        fire_event(ctx, DIDAQT_EVENT_REVIVED, (uint64_t)sids[si],
                   ctx->nodes[s].group_id, 0);
        ctx->runtime[s].seen = 1;
        ctx->runtime[s].seen_at_recv = 1;

        /* Clear any existing USED path for this sender, then activate
         * the path to the receiver that reported it. */
        int start = ctx->sender_path_start[s];
        int count = ctx->sender_path_count[s];
        for (int i = start; i < start + count; i++) {
            if (ctx->paths[i].status == DIDAQT_PATH_USED)
                ctx->paths[i].status = DIDAQT_PATH_AVAILABLE;
        }
        for (int i = start; i < start + count; i++) {
            if (ctx->paths[i].receiver_idx == recv_idx) {
                ctx->paths[i].status = DIDAQT_PATH_USED;
                break;
            }
        }
    }

    /* Track which groups have already been failed over in this heartbeat. */
    memset(ctx->handled_groups, 0, ctx->num_nodes * sizeof(uint32_t));
    int num_handled_groups = 0;

    /* For each sender with a Used path to this receiver.
     * Uses the per-receiver path index for O(paths_at_recv) lookup. */
    int rp_start = ctx->recv_path_start[recv_idx];
    int rp_count = ctx->recv_path_count[recv_idx];
    for (int ri = 0; ri < rp_count; ri++) {
        int i = ctx->recv_path_idx[rp_start + ri];
        ctrl_path *p = &ctx->paths[i];
        if (p->status != DIDAQT_PATH_USED) continue;

        int s = p->sender_idx;
        sender_runtime *rt = &ctx->runtime[s];
        if (rt->dead) continue;
        uint64_t sid = ctx->nodes[s].sender_id;

        /* O(S) scan — acceptable since scnt is bounded by
         * DIDAQT_MAX_SENDERS (256) and this loop runs once per
         * Used path. For larger sender counts a sorted sids[]
         * with binary search would help. */
        int present = 0;
        for (int k = 0; k < scnt; k++) {
            if ((uint64_t)sids[k] == sid) { present = 1; break; }
        }

        if (present) {
            rt->seen = 1;
            if (!rt->seen_at_recv) {
                rt->seen_at_recv = 1;
                /* Fire confirmation if this follows a failover. */
                if (rt->failover_initiated_at.tv_sec != 0 ||
                    rt->failover_initiated_at.tv_nsec != 0) {
                    long confirm_ns = timespec_diff_ns(
                        &now, &rt->failover_initiated_at);
                    fire_event(ctx, DIDAQT_EVENT_CONFIRMED, sid,
                               ctx->nodes[s].group_id, confirm_ns);
                    rt->failover_initiated_at = (struct timespec){0, 0};
                }
            }
            rt->miss_count = 0;
            confirm_failed(ctx, s);
        } else if (rt->seen && !in_grace_period(ctx, s, &now)) {
            rt->miss_count++;
            if (rt->miss_count < ctx->miss_threshold)
                continue;

            uint32_t gid = ctx->nodes[s].group_id;

            /* If this sender was never seen at its current receiver
             * since the last failover, the sender itself is dead —
             * not the path.  Mark it dead individually and revert
             * the group to undo the unnecessary failover. */
            if (!rt->seen_at_recv) {
                rt->dead = 1;
                fire_event(ctx, DIDAQT_EVENT_DEAD, sid,
                           ctx->nodes[s].group_id, 0);
                fprintf(stderr, "sender '%s' (id %lu): never seen at "
                        "current receiver, marked dead\n",
                        ctx->nodes[s].name, (unsigned long)sid);

                if (gid != 0) {
                    int already = 0;
                    for (int g = 0; g < num_handled_groups; g++) {
                        if (ctx->handled_groups[g] == gid) { already = 1; break; }
                    }
                    if (!already) {
                        failover_group(ctx, gid, &now);
                        if (num_handled_groups < ctx->num_nodes)
                            ctx->handled_groups[num_handled_groups++] = gid;
                    }
                }
                continue;
            }

            if (gid != 0) {
                /* Skip if this group was already handled. */
                int already = 0;
                for (int g = 0; g < num_handled_groups; g++) {
                    if (ctx->handled_groups[g] == gid) { already = 1; break; }
                }
                if (!already) {
                    failover_group(ctx, gid, &now);
                    if (num_handled_groups < ctx->num_nodes)
                        ctx->handled_groups[num_handled_groups++] = gid;
                }
            } else {
                failover_sender(ctx, s, i, &now);
            }
        }
    }

    return DIDAQT_OK;
}

int didaqt_ctrl_get_path_statuses(const didaqt_ctrl_ctx *ctx,
                                  didaqt_path_info **out, int *count)
{
    if (!ctx || !out || !count) return DIDAQT_ERR;

    *count = ctx->num_paths;
    if (ctx->num_paths == 0) { *out = NULL; return DIDAQT_OK; }
    *out = calloc(ctx->num_paths, sizeof(didaqt_path_info));
    if (!*out) return DIDAQT_ERR;

    for (int i = 0; i < ctx->num_paths; i++) {
        const ctrl_path *p = &ctx->paths[i];
        didaqt_path_info *pi = &(*out)[i];
        pi->path_id     = i;
        pi->sender_id   = ctx->nodes[p->sender_idx].sender_id;
        pi->receiver_id = ctx->nodes[p->receiver_idx].receiver_id;
        pi->status      = p->status;
        strncpy(pi->sender_name,
                ctx->nodes[p->sender_idx].name, NAME_LEN - 1);
        strncpy(pi->receiver_name,
                ctx->nodes[p->receiver_idx].name, NAME_LEN - 1);
    }

    return DIDAQT_OK;
}

int didaqt_ctrl_set_path_status(didaqt_ctrl_ctx *ctx,
                                int path_id, didaqt_path_status status)
{
    if (!ctx || path_id < 0 || path_id >= ctx->num_paths)
        return DIDAQT_ERR;
    if (status < DIDAQT_PATH_USED || status > DIDAQT_PATH_FAILED)
        return DIDAQT_ERR;
    ctx->paths[path_id].status = status;
    return DIDAQT_OK;
}

int didaqt_ctrl_revive_sender(didaqt_ctrl_ctx *ctx, uint64_t sender_id)
{
    if (!ctx) return DIDAQT_ERR;

    int s = id_lookup_find(ctx->sender_lookup, ctx->num_sender_lookup,
                           sender_id);
    if (s < 0) return DIDAQT_ERR;

    sender_runtime *rt = &ctx->runtime[s];
    rt->dead = 0;
    rt->seen = 0;
    rt->seen_at_recv = 0;
    rt->miss_count = 0;

    /* Reset all FAILED and TEMP_FAILED paths for this sender to
     * AVAILABLE so failover can be attempted again. */
    int start = ctx->sender_path_start[s];
    int count = ctx->sender_path_count[s];
    for (int i = start; i < start + count; i++) {
        if (ctx->paths[i].status == DIDAQT_PATH_FAILED ||
            ctx->paths[i].status == DIDAQT_PATH_TEMP_FAILED)
            ctx->paths[i].status = DIDAQT_PATH_AVAILABLE;
    }

    return DIDAQT_OK;
}

static void free_nodes(topo_node *nodes, int num_nodes)
{
    if (!nodes) return;
    for (int i = 0; i < num_nodes; i++) {
        topo_node *n = &nodes[i];
        if (n->conns) {
            for (int c = 0; c < n->num_conns; c++)
                free(n->conns[c].init_conns);
            free(n->conns);
        }
    }
    free(nodes);
}

void didaqt_ctrl_destroy(didaqt_ctrl_ctx *ctx)
{
    if (!ctx) return;
    free_nodes(ctx->nodes, ctx->num_nodes);
    if (ctx->paths) {
        for (int i = 0; i < ctx->num_paths; i++)
            free(ctx->paths[i].hops);
        free(ctx->paths);
    }
    free(ctx->sender_path_start);
    free(ctx->sender_path_count);
    free(ctx->recv_path_idx);
    free(ctx->recv_path_start);
    free(ctx->recv_path_count);
    free(ctx->runtime);
    free(ctx->handled_groups);
    free(ctx->rollback_buf);
    free(ctx->sender_lookup);
    free(ctx->recv_lookup);
    free(ctx->handlers);
    free(ctx);
}
