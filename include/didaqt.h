#ifndef DIDAQT_H
#define DIDAQT_H

#include <stdint.h>
#include <netinet/in.h>

/*
 * DiDAQt — Distributed Resilience for Data Acquisition Systems
 *
 * Receiver-side API: receivers monitor connections to upstream senders
 * and periodically emit heartbeat packets to the controller over an
 * out-of-band UDP channel.
 */

/* Maximum number of senders a single receiver can track. */
#define DIDAQT_MAX_SENDERS 256

/* Default heartbeat interval in milliseconds. */
#define DIDAQT_DEFAULT_HB_INTERVAL_MS 100

/* Return codes. */
#define DIDAQT_OK        0
#define DIDAQT_ERR      -1
#define DIDAQT_ERR_FULL -2

/*
 * Heartbeat packet payload (sent from R to C).
 *
 * Layout:
 *   [0..3]  receiver_id   (network byte order)
 *   [4..5]  sender_count  (network byte order)
 *   [6..]   array of sender_ids, each uint32_t (network byte order)
 */

typedef struct didaqt_rx_ctx didaqt_rx_ctx;

/*
 * didaqt_rx_init_ctx — Create a receiver context.
 *
 * Allocates and initialises a context on a Receiver that tracks which
 * senders are healthy.  The heartbeat thread is NOT started until
 * didaqt_rx_start() is called, allowing the caller to configure the
 * context first (destination address, interval, etc.).
 *
 *   r_id  — unique identifier for this receiver
 *   ctx   — out-pointer; set to the newly allocated context on success
 *
 * Returns DIDAQT_OK on success, DIDAQT_ERR on failure.
 */
int didaqt_rx_init_ctx(uint32_t r_id, didaqt_rx_ctx **ctx);

/*
 * didaqt_rx_set_controller — Set the controller destination address.
 *
 * Must be called before didaqt_rx_start().
 */
int didaqt_rx_set_controller(didaqt_rx_ctx *ctx,
                             const char *ip, uint16_t port);

/*
 * didaqt_rx_set_interval — Set the heartbeat interval in milliseconds.
 *
 * Must be called before didaqt_rx_start().  Defaults to
 * DIDAQT_DEFAULT_HB_INTERVAL_MS if not called.
 */
int didaqt_rx_set_interval(didaqt_rx_ctx *ctx, uint32_t interval_ms);

/*
 * didaqt_rx_start — Start the heartbeat background thread.
 *
 * After this call the context will periodically send a UDP heartbeat
 * containing every sender ID that was scheduled since the last beat.
 * The set of scheduled senders is cleared after each heartbeat.
 *
 * Returns DIDAQT_OK on success, DIDAQT_ERR on failure.
 */
int didaqt_rx_start(didaqt_rx_ctx *ctx);

/*
 * schedule_heartbeat — Mark a sender connection as healthy.
 *
 * Call this from the user processing path whenever data is
 * successfully received from sender s_id.  On the next heartbeat
 * interval, s_id will be included in the heartbeat packet sent
 * to the controller.
 *
 * Returns DIDAQT_OK on success, DIDAQT_ERR_FULL if the sender table
 * is at capacity.
 */
int schedule_heartbeat(uint32_t s_id, didaqt_rx_ctx *ctx);

/*
 * didaqt_rx_stop — Stop the heartbeat thread and release resources.
 *
 * Blocks until the background thread exits.  After this call the
 * context pointer is invalid.
 */
void didaqt_rx_stop(didaqt_rx_ctx *ctx);

#endif /* DIDAQT_H */
