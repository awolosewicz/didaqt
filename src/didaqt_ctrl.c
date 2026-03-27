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

struct didaqt_ctrl_ctx {
    topo_node   *nodes;
    int          num_nodes;

    ctrl_path   *paths;
    int          num_paths;
    int          max_paths;      /* current allocation size */

    /* Post-failover grace period in nanoseconds. */
    long         grace_period_ns;

    /* Per-node arrays (allocated to num_nodes after YAML parse). */
    int              *sender_dead;
    int              *sender_seen;           /* ever seen in any heartbeat */
    int              *sender_seen_at_recv;   /* seen at current receiver since last failover */
    struct timespec  *last_failover;

    ctrl_handler *handlers;
    int           num_handlers;
    int           max_handlers;
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

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

        const char *on = map_str(doc, val, "other_node");
        if (on) strncpy(c->other_node, on, NAME_LEN - 1);

        const char *op = map_str(doc, val, "other_port");
        if (op) c->other_port = atoi(op);

        const char *bw = map_str(doc, val, "max_bandwidth");
        if (bw) c->max_bandwidth = parse_bandwidth(bw);

        yaml_node_t *ic = map_get(doc, val, "initial_connections");
        if (ic) parse_init_conns(doc, ic, c);
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

    /* Bandwidth symmetry. */
    for (int i = 0; i < ctx->num_nodes; i++) {
        for (int c = 0; c < ctx->nodes[i].num_conns; c++) {
            connection *ca = &ctx->nodes[i].conns[c];
            int j = find_node(ctx, ca->other_node);
            if (j < 0) {
                fprintf(stderr, "'%s' connection references unknown node '%s'\n",
                        ctx->nodes[i].name, ca->other_node);
                err = 1;
                continue;
            }
            for (int c2 = 0; c2 < ctx->nodes[j].num_conns; c2++) {
                connection *cb = &ctx->nodes[j].conns[c2];
                if (cb->other_port == ca->port_num &&
                    strcmp(cb->other_node, ctx->nodes[i].name) == 0) {
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
            ctrl_path *p = &ctx->paths[ctx->num_paths];
            p->sender_idx   = sender_idx;
            p->receiver_idx = cur_node;
            p->num_hops     = num_hops;
            p->hops = malloc(num_hops * sizeof(path_hop));
            if (p->hops)
                memcpy(p->hops, hops, num_hops * sizeof(path_hop));
            p->status = DIDAQT_PATH_AVAILABLE;
            ctx->num_paths++;
        }
    }

    /* If this node can forward traffic, continue the search. */
    if (node_forwards(n)) {
        for (int c = 0; c < n->num_conns; c++) {
            connection *conn = &n->conns[c];
            if (conn->port_num == arrived_port) continue;

            int next = find_node(ctx, conn->other_node);
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

static void find_all_paths(didaqt_ctrl_ctx *ctx)
{
    int *visited = calloc(ctx->num_nodes, sizeof(int));
    if (!visited) return;

    /* DFS depth is bounded by the number of nodes (visited check). */
    path_hop *hops = malloc(ctx->num_nodes * sizeof(path_hop));
    if (!hops) { free(visited); return; }

    for (int s = 0; s < ctx->num_nodes; s++) {
        if (!node_is_sender(&ctx->nodes[s])) continue;

        for (int c = 0; c < ctx->nodes[s].num_conns; c++) {
            connection *conn = &ctx->nodes[s].conns[c];
            int next = find_node(ctx, conn->other_node);
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
}

/* ------------------------------------------------------------------ */
/*  Path ordering                                                      */
/* ------------------------------------------------------------------ */

static void compute_ordering(didaqt_ctrl_ctx *ctx)
{
    for (int i = 0; i < ctx->num_paths; i++) {
        ctrl_path *p = &ctx->paths[i];

        /* switch_updates = number of switch hops */
        p->switch_updates = p->num_hops;

        /* contention = number of OTHER senders that also have any
         * path ending at the same receiver. */
        int cont = 0;
        for (int j = 0; j < ctx->num_paths; j++) {
            if (j == i) continue;
            if (ctx->paths[j].receiver_idx != p->receiver_idx) continue;
            if (ctx->paths[j].sender_idx == p->sender_idx) continue;
            /* Count each distinct sender only once. */
            int already = 0;
            for (int k = 0; k < j; k++) {
                if (k == i) continue;
                if (ctx->paths[k].receiver_idx == p->receiver_idx &&
                    ctx->paths[k].sender_idx == ctx->paths[j].sender_idx) {
                    already = 1;
                    break;
                }
            }
            if (!already) cont++;
        }
        p->contention = cont;
    }

    /* Sort paths for each sender: contention asc, switch_updates asc.
     * Use a simple insertion sort grouped by sender. */
    for (int s = 0; s < ctx->num_nodes; s++) {
        if (!node_is_sender(&ctx->nodes[s])) continue;

        /* Gather indices of paths for this sender. */
        int *idx = malloc(ctx->num_paths * sizeof(int));
        if (!idx) return;
        int cnt = 0;
        for (int i = 0; i < ctx->num_paths; i++)
            if (ctx->paths[i].sender_idx == s)
                idx[cnt++] = i;

        /* Insertion sort on the gathered indices. */
        for (int a = 1; a < cnt; a++) {
            int ai = idx[a];
            ctrl_path tmp = ctx->paths[ai];
            int b = a - 1;
            while (b >= 0) {
                int bi = idx[b];
                ctrl_path *bp = &ctx->paths[bi];
                if (bp->contention < tmp.contention) break;
                if (bp->contention == tmp.contention &&
                    bp->switch_updates <= tmp.switch_updates) break;
                ctx->paths[idx[b + 1]] = *bp;
                b--;
            }
            ctx->paths[idx[b + 1]] = tmp;
        }
        free(idx);
    }
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

        /* Find the path to the initial receiver.  If multiple paths go
         * to the same receiver, pick the first (best-ordered) one. */
        for (int i = 0; i < ctx->num_paths; i++) {
            if (ctx->paths[i].sender_idx == s &&
                ctx->paths[i].receiver_idx == target) {
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

/* Find the receiver node index by its integer receiver_id. */
static int find_receiver_by_id(const didaqt_ctrl_ctx *ctx, uint32_t rid)
{
    for (int i = 0; i < ctx->num_nodes; i++) {
        if (node_is_receiver(&ctx->nodes[i]) &&
            ctx->nodes[i].receiver_id == rid)
            return i;
    }
    return -1;
}

/* Check if sender_id appears in a heartbeat sender list. */
static int sender_in_list(uint64_t sid, const uint32_t *list, int count)
{
    for (int i = 0; i < count; i++)
        if ((uint64_t)list[i] == sid)
            return 1;
    return 0;
}

/* Find the first Available path for a sender (they are pre-sorted). */
static int first_available(const didaqt_ctrl_ctx *ctx, int sender_idx)
{
    for (int i = 0; i < ctx->num_paths; i++)
        if (ctx->paths[i].sender_idx == sender_idx &&
            ctx->paths[i].status == DIDAQT_PATH_AVAILABLE)
            return i;
    return -1;
}

/* Move all TempFailed for a sender to Failed (confirmed dead). */
static void confirm_failed(didaqt_ctrl_ctx *ctx, int sender_idx)
{
    for (int i = 0; i < ctx->num_paths; i++)
        if (ctx->paths[i].sender_idx == sender_idx &&
            ctx->paths[i].status == DIDAQT_PATH_TEMP_FAILED)
            ctx->paths[i].status = DIDAQT_PATH_FAILED;
}

/* Record a failover timestamp for a sender (starts the grace period). */
static void mark_failover_time(didaqt_ctrl_ctx *ctx, int sender_idx)
{
    clock_gettime(CLOCK_MONOTONIC, &ctx->last_failover[sender_idx]);
}

/* Check if a sender is within the post-failover grace period. */
static int in_grace_period(const didaqt_ctrl_ctx *ctx, int sender_idx)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ns = (now.tv_sec  - ctx->last_failover[sender_idx].tv_sec) * 1000000000L
                    + (now.tv_nsec - ctx->last_failover[sender_idx].tv_nsec);
    return elapsed_ns < ctx->grace_period_ns;
}

/* Recycle Failed paths back to Available for a sender.
 * TempFailed paths are NOT recycled — if every failover attempt
 * for a sender fails (all paths go TempFailed), the sender must
 * be assumed dead. */
static void recycle_failed(didaqt_ctrl_ctx *ctx, int sender_idx)
{
    for (int i = 0; i < ctx->num_paths; i++)
        if (ctx->paths[i].sender_idx == sender_idx &&
            ctx->paths[i].status == DIDAQT_PATH_FAILED)
            ctx->paths[i].status = DIDAQT_PATH_AVAILABLE;
}

/* Perform failover for a single (ungrouped) sender. */
static void failover_sender(didaqt_ctrl_ctx *ctx, int sender_idx,
                            int old_path_idx)
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
        if (execute_failover(ctx, sid, old, &ctx->paths[new_idx]) != 0) {
            /* Switch update failed — rollback path state. */
            old->status = DIDAQT_PATH_USED;
            ctx->paths[new_idx].status = DIDAQT_PATH_AVAILABLE;
            fprintf(stderr, "sender '%s' (id %lu): switch update failed, "
                    "rollback\n",
                    ctx->nodes[sender_idx].name, (unsigned long)sid);
            return;
        }
        mark_failover_time(ctx, sender_idx);
        ctx->sender_seen_at_recv[sender_idx] = 0;
    } else {
        /* Still nothing — all paths are TempFailed, sender is dead. */
        ctx->sender_dead[sender_idx] = 1;
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
static void failover_group(didaqt_ctrl_ctx *ctx, uint32_t group_id)
{
    /* Find a representative sender and its current Used path. */
    int rep = -1, rep_old = -1;
    for (int s = 0; s < ctx->num_nodes && rep < 0; s++) {
        if (!node_is_sender(&ctx->nodes[s])) continue;
        if (ctx->nodes[s].group_id != group_id) continue;
        for (int i = 0; i < ctx->num_paths; i++) {
            if (ctx->paths[i].sender_idx == s &&
                ctx->paths[i].status == DIDAQT_PATH_USED) {
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
            ctx->sender_dead[s] = 1;
        }
        fprintf(stderr, "group %u: all paths exhausted\n", group_id);
        return;
    }

    int new_receiver = ctx->paths[rep_new].receiver_idx;

    /* Snapshot path statuses before modification for rollback. */
    didaqt_path_status *saved = malloc(ctx->num_paths
                                       * sizeof(didaqt_path_status));
    if (!saved) return;
    for (int i = 0; i < ctx->num_paths; i++)
        saved[i] = ctx->paths[i].status;

    /* Move ALL senders in the group: Used→TempFailed, new path→Used. */
    for (int s = 0; s < ctx->num_nodes; s++) {
        if (!node_is_sender(&ctx->nodes[s])) continue;
        if (ctx->nodes[s].group_id != group_id) continue;

        /* TempFail the current Used path. */
        for (int i = 0; i < ctx->num_paths; i++) {
            if (ctx->paths[i].sender_idx == s &&
                ctx->paths[i].status == DIDAQT_PATH_USED) {
                ctx->paths[i].status = DIDAQT_PATH_TEMP_FAILED;
                break;
            }
        }

        /* Activate the path to the new receiver.  The path may be
         * AVAILABLE (normal case) or TEMP_FAILED/FAILED if this sender
         * never appeared at the new receiver to confirm a previous
         * failover (e.g. a dead sender in a group). */
        for (int i = 0; i < ctx->num_paths; i++) {
            if (ctx->paths[i].sender_idx == s &&
                ctx->paths[i].receiver_idx == new_receiver) {
                ctx->paths[i].status = DIDAQT_PATH_USED;
                break;
            }
        }

        mark_failover_time(ctx, s);
        ctx->sender_seen_at_recv[s] = 0;
    }

    /* ONE switch update using the representative's old/new paths. */
    if (execute_failover(ctx, ctx->nodes[rep].sender_id,
                         &ctx->paths[rep_old], &ctx->paths[rep_new]) != 0) {
        /* Switch update failed — rollback ALL path statuses. */
        for (int i = 0; i < ctx->num_paths; i++)
            ctx->paths[i].status = saved[i];
        fprintf(stderr, "group %u: switch update failed, rollback\n",
                group_id);
    }
    free(saved);
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

    *ctx = c;
    return DIDAQT_OK;
}

int didaqt_ctrl_set_grace_period(didaqt_ctrl_ctx *ctx, long grace_ns)
{
    if (!ctx || grace_ns < 0) return DIDAQT_ERR;
    ctx->grace_period_ns = grace_ns;
    return DIDAQT_OK;
}

/* Allocate per-node runtime arrays after YAML parse. */
static int alloc_node_arrays(didaqt_ctrl_ctx *ctx)
{
    int n = ctx->num_nodes;
    ctx->sender_dead         = calloc(n, sizeof(int));
    ctx->sender_seen         = calloc(n, sizeof(int));
    ctx->sender_seen_at_recv = calloc(n, sizeof(int));
    ctx->last_failover       = calloc(n, sizeof(struct timespec));
    if (!ctx->sender_dead || !ctx->sender_seen ||
        !ctx->sender_seen_at_recv || !ctx->last_failover)
        return DIDAQT_ERR;
    return DIDAQT_OK;
}

int didaqt_ctrl_process_topology(const char *yaml_path,
                                 didaqt_ctrl_ctx *ctx)
{
    if (!ctx || !yaml_path) return DIDAQT_ERR;

    int rc = parse_yaml(yaml_path, ctx);
    if (rc != DIDAQT_OK) return rc;

    rc = alloc_node_arrays(ctx);
    if (rc != DIDAQT_OK) return rc;

    rc = validate(ctx);
    if (rc != DIDAQT_OK) return rc;

    find_all_paths(ctx);
    compute_ordering(ctx);
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

    int recv_idx = find_receiver_by_id(ctx, rid);
    if (recv_idx < 0) return DIDAQT_ERR;

    /* Auto-revive dead senders that reappear in this heartbeat.
     * Iterate over the senders reported in the heartbeat and check
     * if any are dead.  If so, revive and set their path to this
     * receiver as USED. */
    for (int si = 0; si < scnt; si++) {
        /* Find the sender node by sender_id. */
        int s = -1;
        for (int n = 0; n < ctx->num_nodes; n++) {
            if (node_is_sender(&ctx->nodes[n]) &&
                ctx->nodes[n].sender_id == (uint64_t)sids[si]) {
                s = n;
                break;
            }
        }
        if (s < 0 || !ctx->sender_dead[s]) continue;

        didaqt_ctrl_revive_sender(ctx, (uint64_t)sids[si]);
        ctx->sender_seen[s] = 1;
        ctx->sender_seen_at_recv[s] = 1;

        /* Clear any existing USED path for this sender, then activate
         * the path to the receiver that reported it. */
        for (int i = 0; i < ctx->num_paths; i++) {
            if (ctx->paths[i].sender_idx == s &&
                ctx->paths[i].status == DIDAQT_PATH_USED)
                ctx->paths[i].status = DIDAQT_PATH_AVAILABLE;
        }
        for (int i = 0; i < ctx->num_paths; i++) {
            if (ctx->paths[i].sender_idx == s &&
                ctx->paths[i].receiver_idx == recv_idx) {
                ctx->paths[i].status = DIDAQT_PATH_USED;
                break;
            }
        }
    }

    /* Track which groups have already been failed over in this
     * heartbeat to avoid processing the same group multiple times. */
    uint32_t *handled_groups = calloc(ctx->num_nodes, sizeof(uint32_t));
    if (!handled_groups) return DIDAQT_ERR;
    int num_handled_groups = 0;

    /* For each sender with a Used path to this receiver: */
    for (int i = 0; i < ctx->num_paths; i++) {
        ctrl_path *p = &ctx->paths[i];
        if (p->receiver_idx != recv_idx) continue;
        if (p->status != DIDAQT_PATH_USED) continue;

        int s = p->sender_idx;
        if (ctx->sender_dead[s]) continue;
        uint64_t sid = ctx->nodes[s].sender_id;

        if (sender_in_list(sid, sids, scnt)) {
            ctx->sender_seen[s] = 1;
            ctx->sender_seen_at_recv[s] = 1;
            confirm_failed(ctx, s);
        } else if (ctx->sender_seen[s] && !in_grace_period(ctx, s)) {
            uint32_t gid = ctx->nodes[s].group_id;

            /* If this sender was never seen at its current receiver
             * since the last failover, the sender itself is dead —
             * not the path.  Mark it dead individually without
             * triggering a group failover. */
            if (!ctx->sender_seen_at_recv[s]) {
                ctx->sender_dead[s] = 1;
                fprintf(stderr, "sender '%s' (id %lu): never seen at "
                        "current receiver, marked dead\n",
                        ctx->nodes[s].name, (unsigned long)sid);
                continue;
            }

            if (gid != 0) {
                /* Skip if this group was already handled. */
                int already = 0;
                for (int g = 0; g < num_handled_groups; g++) {
                    if (handled_groups[g] == gid) { already = 1; break; }
                }
                if (!already) {
                    failover_group(ctx, gid);
                    if (num_handled_groups < ctx->num_nodes)
                        handled_groups[num_handled_groups++] = gid;
                }
            } else {
                failover_sender(ctx, s, i);
            }
        }
    }

    free(handled_groups);
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
        pi->path_id   = i;
        pi->sender_id = ctx->nodes[p->sender_idx].sender_id;
        pi->status    = p->status;
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

    int s = -1;
    for (int i = 0; i < ctx->num_nodes; i++) {
        if (node_is_sender(&ctx->nodes[i]) &&
            ctx->nodes[i].sender_id == sender_id) {
            s = i;
            break;
        }
    }
    if (s < 0) return DIDAQT_ERR;

    ctx->sender_dead[s] = 0;
    ctx->sender_seen[s] = 0;
    ctx->sender_seen_at_recv[s] = 0;

    /* Reset all FAILED and TEMP_FAILED paths for this sender to
     * AVAILABLE so failover can be attempted again. */
    for (int i = 0; i < ctx->num_paths; i++) {
        if (ctx->paths[i].sender_idx != s) continue;
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
    free(ctx->sender_dead);
    free(ctx->sender_seen);
    free(ctx->sender_seen_at_recv);
    free(ctx->last_failover);
    free(ctx->handlers);
    free(ctx);
}
