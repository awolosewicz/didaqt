#ifndef DIDAQT_H
#define DIDAQT_H

#include <stdint.h>
#include <netinet/in.h>

/*
 * DiDAQt — Distributed Resilience for Data Acquisition Systems
 */

/* Maximum number of senders a single receiver can track. */
#define DIDAQT_MAX_SENDERS 256

/* Default heartbeat interval in milliseconds. */
#define DIDAQT_DEFAULT_HB_INTERVAL_MS 100

/* Return codes. */
#define DIDAQT_OK        0
#define DIDAQT_ERR      -1
#define DIDAQT_ERR_FULL -2

/* ------------------------------------------------------------------ */
/*  Receiver-side API                                                  */
/* ------------------------------------------------------------------ */

/*
 * Heartbeat packet payload (sent from R to C).
 *
 * Layout:
 *   [0..3]  receiver_id   (network byte order)
 *   [4..5]  sender_count  (network byte order)
 *   [6..]   array of sender_ids, each uint32_t (network byte order)
 */

typedef struct didaqt_rx_ctx didaqt_rx_ctx;

int didaqt_rx_init_ctx(uint32_t r_id, didaqt_rx_ctx **ctx);
int didaqt_rx_set_controller(didaqt_rx_ctx *ctx,
                             const char *ip, uint16_t port);
int didaqt_rx_set_interval(didaqt_rx_ctx *ctx, uint32_t interval_ms);
int didaqt_rx_start(didaqt_rx_ctx *ctx);
int schedule_heartbeat(uint32_t s_id, didaqt_rx_ctx *ctx);

/*
 * deschedule_heartbeat — Mark a sender connection as unhealthy.
 *
 * Removes s_id from the scheduled set for the current heartbeat
 * interval AND blocks any subsequent schedule_heartbeat() calls
 * for s_id until the next interval.  This guarantees that even a
 * single bad packet within an interval prevents that sender from
 * appearing in the heartbeat, regardless of how many good packets
 * arrive before or after.
 *
 * The block is automatically cleared when the heartbeat fires.
 */
int deschedule_heartbeat(uint32_t s_id, didaqt_rx_ctx *ctx);

void didaqt_rx_stop(didaqt_rx_ctx *ctx);

/* ------------------------------------------------------------------ */
/*  Controller-side API                                                */
/* ------------------------------------------------------------------ */

/* Path status for sender→receiver paths. */
typedef enum {
    DIDAQT_PATH_USED        = 0,
    DIDAQT_PATH_AVAILABLE   = 1,
    DIDAQT_PATH_TEMP_FAILED = 2,
    DIDAQT_PATH_FAILED      = 3,
} didaqt_path_status;

#define DIDAQT_MAX_NAME 64

/* Default controller settings. */
#define DIDAQT_DEFAULT_GRACE_PERIOD_NS 1000000000L  /* 1 second */
#define DIDAQT_DEFAULT_MISS_THRESHOLD  3

/* Opaque controller context. */
typedef struct didaqt_ctrl_ctx didaqt_ctrl_ctx;

/*
 * Switch handler callback — invoked per switch when executing a
 * failover.  switch_name is the topology node name of the switch
 * being updated.  Port values are -1 when the switch is not part
 * of that path (i.e. pure add or pure remove).
 */
typedef int (*didaqt_switch_handler_fn)(
    const char *switch_name,
    uint64_t sender_id,
    int cur_ingress, int cur_egress,
    int new_ingress, int new_egress,
    void *user_data);

/* Snapshot of a single path returned by didaqt_ctrl_get_path_statuses. */
typedef struct {
    int                path_id;
    uint64_t           sender_id;
    uint32_t           receiver_id;
    char               sender_name[DIDAQT_MAX_NAME];
    char               receiver_name[DIDAQT_MAX_NAME];
    didaqt_path_status status;
} didaqt_path_info;

/* Failover event types reported via the event callback. */
typedef enum {
    DIDAQT_EVENT_FAILOVER,    /* failover decision + switch update */
    DIDAQT_EVENT_CONFIRMED,   /* sender confirmed at new receiver  */
    DIDAQT_EVENT_DEAD,        /* sender marked dead                */
    DIDAQT_EVENT_REVIVED,     /* dead sender auto-revived          */
} didaqt_event_type;

typedef struct {
    didaqt_event_type type;
    uint64_t sender_id;   /* 0 for group-level DEAD events */
    uint32_t group_id;
    long     elapsed_ns;  /* FAILOVER:  decision time before switch update
                             CONFIRMED: time since switch update completed
                             DEAD:      0
                             REVIVED:   0 */
} didaqt_event;

typedef void (*didaqt_event_fn)(const didaqt_event *event, void *user_data);

/*
 * didaqt_ctrl_init_ctx — Allocate a controller context.
 */
int didaqt_ctrl_init_ctx(didaqt_ctrl_ctx **ctx);

/*
 * didaqt_ctrl_set_event_callback — Register a callback for failover events.
 * The callback is invoked synchronously during process_heartbeat.
 */
int didaqt_ctrl_set_event_callback(didaqt_ctrl_ctx *ctx,
                                    didaqt_event_fn fn, void *user_data);

/*
 * didaqt_ctrl_set_grace_period — Set the post-failover grace period
 * in nanoseconds.  After a failover, the affected sender's absence
 * from heartbeats is ignored for this duration.
 * Default: DIDAQT_DEFAULT_GRACE_PERIOD_NS (1 second).
 */
int didaqt_ctrl_set_grace_period(didaqt_ctrl_ctx *ctx, long grace_ns);

/*
 * didaqt_ctrl_set_miss_threshold — Set the number of consecutive
 * heartbeats a sender must be absent from before triggering failover.
 * Default: DIDAQT_DEFAULT_MISS_THRESHOLD (3).
 */
int didaqt_ctrl_set_miss_threshold(didaqt_ctrl_ctx *ctx, int threshold);

/*
 * didaqt_ctrl_process_topology — Parse a YAML topology file and
 * run static reachability analysis.
 *
 * Builds all sender→receiver paths, orders them by contention
 * then by number of switch updates, and sets initial path states.
 */
int didaqt_ctrl_process_topology(const char *yaml_path,
                                 didaqt_ctrl_ctx *ctx);

/*
 * didaqt_ctrl_register_handler — Register a failover handler for
 * switches of the given switch_type_group.
 */
int didaqt_ctrl_register_handler(didaqt_ctrl_ctx *ctx,
                                 const char *switch_type_group,
                                 didaqt_switch_handler_fn fn,
                                 void *user_data);

/*
 * didaqt_ctrl_process_heartbeat — Feed a received heartbeat packet
 * to the controller.  Triggers failover logic if senders are missing
 * from a configurable number of consecutive heartbeats (default 3,
 * see set_miss_threshold).
 *
 * After a failover, the affected sender's absence is ignored for a
 * configurable grace period (default 1s, see set_grace_period) to
 * allow traffic to reach the new receiver.
 * Senders must appear in at least one heartbeat before their absence
 * can trigger a failover.
 */
int didaqt_ctrl_process_heartbeat(const uint8_t *buf, size_t len,
                                  didaqt_ctrl_ctx *ctx);

/*
 * didaqt_ctrl_get_path_statuses — Return a snapshot of all path
 * statuses.  Caller must free(*out) when done.
 */
int didaqt_ctrl_get_path_statuses(const didaqt_ctrl_ctx *ctx,
                                  didaqt_path_info **out, int *count);

/*
 * didaqt_ctrl_set_path_status — Manually override a path's status.
 */
int didaqt_ctrl_set_path_status(didaqt_ctrl_ctx *ctx,
                                int path_id, didaqt_path_status status);

/*
 * didaqt_ctrl_revive_sender — Remove a sender from the dead state.
 *
 * When all paths for a sender are exhausted the sender is marked
 * dead and ignored by heartbeat processing.  This function clears
 * that flag and resets all FAILED/TEMP_FAILED paths for the sender
 * back to AVAILABLE so that failover can be attempted again.
 *
 * Also resets the sender's 'seen' flag, meaning the sender must
 * appear in at least one heartbeat after revival before its absence
 * can trigger a new failover.
 */
int didaqt_ctrl_revive_sender(didaqt_ctrl_ctx *ctx, uint64_t sender_id);

/*
 * didaqt_ctrl_get_ordering_time — Return the wall-clock time in
 * nanoseconds spent in the compute_ordering step of process_topology.
 * Only valid after a successful process_topology call.
 */
long didaqt_ctrl_get_ordering_time(const didaqt_ctrl_ctx *ctx);

/*
 * didaqt_ctrl_destroy — Free all resources.
 */
void didaqt_ctrl_destroy(didaqt_ctrl_ctx *ctx);

#endif /* DIDAQT_H */
