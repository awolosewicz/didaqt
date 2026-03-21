/*
 * controller.c — Example network controller for Tofino 2 switches
 *
 * Manages L2 forwarding tables on Tofino 2 switches via the BF
 * Runtime (bfrt) C API.  Provides:
 *
 *   1. Initial configuration: populates l2_forward table entries so
 *      each receiver's MAC maps to the correct egress port on every
 *      switch in the path.
 *
 *   2. Runtime updates: add/modify/delete individual forwarding
 *      entries.  This is the hook point for integrating the DiDAQt
 *      controller API — when a fail-over is needed, the controller
 *      calls update_l2_entry() to reroute traffic.
 *
 * This code links against the Intel Barefoot SDE.  Build with:
 *   gcc -O2 -Wall -I$SDE_INSTALL/include \
 *       -L$SDE_INSTALL/lib -o controller controller.c \
 *       -lbf_switchd_lib -lbfrt -lpthread
 *
 * Usage:
 *   ./controller <config_file>
 *
 * The config file is a simple text format (one entry per line):
 *   <mac_address> <egress_port>
 * Example:
 *   00:11:22:33:44:55 128
 *   00:11:22:33:44:66 136
 *
 * After loading the initial config, the controller listens on a TCP
 * socket for runtime update commands:
 *   ADD <mac> <port>
 *   MOD <mac> <port>
 *   DEL <mac>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <bf_rt/bf_rt.h>

/* --------------------------------------------------------------- */
/*  Constants                                                       */
/* --------------------------------------------------------------- */

#define P4_PROG_NAME    "l2_forward"
#define TABLE_NAME      "Ingress.l2_forward"
#define ACTION_FWD      "Ingress.forward"
#define ACTION_DROP     "Ingress.drop"

#define CMD_PORT        9100          /* TCP port for runtime commands */
#define CMD_BUF_LEN     256
#define MAX_INIT_ENTRIES 1024

static volatile int running = 1;

/* --------------------------------------------------------------- */
/*  BF Runtime handles (initialised once)                           */
/* --------------------------------------------------------------- */

static const bf_rt_info_hdl   *bfrt_info   = NULL;
static bf_rt_session_hdl      *session     = NULL;
static bf_rt_target_t          dev_tgt     = {0, BF_DEV_PIPE_ALL};
static const bf_rt_table_hdl  *l2_table    = NULL;

static bf_rt_id_t fid_dst_addr;    /* key field:  hdr.ethernet.dst_addr */
static bf_rt_id_t aid_forward;     /* action ID:  forward               */
static bf_rt_id_t aid_drop;        /* action ID:  drop                  */
static bf_rt_id_t did_port;        /* data field: port (in forward)     */

static void handle_signal(int sig) { (void)sig; running = 0; }

/* --------------------------------------------------------------- */
/*  MAC parsing                                                     */
/* --------------------------------------------------------------- */

static int parse_mac(const char *str, uint8_t mac[6])
{
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)m[i];
    return 0;
}

/* --------------------------------------------------------------- */
/*  BF Runtime initialisation                                       */
/* --------------------------------------------------------------- */

static int bfrt_setup(void)
{
    bf_status_t rc;

    /* Create a session. */
    rc = bf_rt_session_create(&session);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "bf_rt_session_create failed: %d\n", rc);
        return -1;
    }

    /* Get the bfrt_info for our P4 program. */
    rc = bf_rt_info_get(dev_tgt.dev_id, P4_PROG_NAME, &bfrt_info);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "bf_rt_info_get(%s) failed: %d\n",
                P4_PROG_NAME, rc);
        return -1;
    }

    /* Look up the l2_forward table. */
    rc = bf_rt_table_from_name_get(bfrt_info, TABLE_NAME, &l2_table);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "table lookup '%s' failed: %d\n", TABLE_NAME, rc);
        return -1;
    }

    /* Resolve field/action IDs. */
    rc = bf_rt_key_field_id_get(l2_table, "hdr.ethernet.dst_addr",
                                &fid_dst_addr);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "key field lookup failed: %d\n", rc);
        return -1;
    }

    rc = bf_rt_action_id_get(l2_table, ACTION_FWD, &aid_forward);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "action '%s' lookup failed: %d\n", ACTION_FWD, rc);
        return -1;
    }

    rc = bf_rt_action_id_get(l2_table, ACTION_DROP, &aid_drop);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "action '%s' lookup failed: %d\n",
                ACTION_DROP, rc);
        return -1;
    }

    rc = bf_rt_data_field_id_with_action_get(l2_table, "port",
                                             aid_forward, &did_port);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "data field 'port' lookup failed: %d\n", rc);
        return -1;
    }

    return 0;
}

/* --------------------------------------------------------------- */
/*  Table operations                                                */
/* --------------------------------------------------------------- */

static int add_l2_entry(const uint8_t mac[6], uint32_t port)
{
    bf_status_t rc;

    bf_rt_table_key_hdl *key = NULL;
    bf_rt_table_data_hdl *data = NULL;

    rc = bf_rt_table_key_allocate(l2_table, &key);
    if (rc != BF_SUCCESS) return -1;

    rc = bf_rt_table_data_allocate_with_action(l2_table, aid_forward,
                                               &data);
    if (rc != BF_SUCCESS) goto err_key;

    /* Set key: dst_addr (6 bytes, network order). */
    rc = bf_rt_key_field_set_value_ptr(key, fid_dst_addr, mac, 6);
    if (rc != BF_SUCCESS) goto err_data;

    /* Set data: egress port. */
    rc = bf_rt_data_field_set_value(data, did_port, (uint64_t)port);
    if (rc != BF_SUCCESS) goto err_data;

    rc = bf_rt_table_entry_add(l2_table, session, &dev_tgt, 0,
                               key, data);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "entry_add failed: %d\n", rc);
        goto err_data;
    }

    bf_rt_table_data_deallocate(data);
    bf_rt_table_key_deallocate(key);
    return 0;

err_data:
    bf_rt_table_data_deallocate(data);
err_key:
    bf_rt_table_key_deallocate(key);
    return -1;
}

static int mod_l2_entry(const uint8_t mac[6], uint32_t port)
{
    bf_status_t rc;

    bf_rt_table_key_hdl *key = NULL;
    bf_rt_table_data_hdl *data = NULL;

    rc = bf_rt_table_key_allocate(l2_table, &key);
    if (rc != BF_SUCCESS) return -1;

    rc = bf_rt_table_data_allocate_with_action(l2_table, aid_forward,
                                               &data);
    if (rc != BF_SUCCESS) goto err_key;

    rc = bf_rt_key_field_set_value_ptr(key, fid_dst_addr, mac, 6);
    if (rc != BF_SUCCESS) goto err_data;

    rc = bf_rt_data_field_set_value(data, did_port, (uint64_t)port);
    if (rc != BF_SUCCESS) goto err_data;

    rc = bf_rt_table_entry_mod(l2_table, session, &dev_tgt, 0,
                               key, data);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "entry_mod failed: %d\n", rc);
        goto err_data;
    }

    bf_rt_table_data_deallocate(data);
    bf_rt_table_key_deallocate(key);
    return 0;

err_data:
    bf_rt_table_data_deallocate(data);
err_key:
    bf_rt_table_key_deallocate(key);
    return -1;
}

static int del_l2_entry(const uint8_t mac[6])
{
    bf_status_t rc;

    bf_rt_table_key_hdl *key = NULL;

    rc = bf_rt_table_key_allocate(l2_table, &key);
    if (rc != BF_SUCCESS) return -1;

    rc = bf_rt_key_field_set_value_ptr(key, fid_dst_addr, mac, 6);
    if (rc != BF_SUCCESS) goto err;

    rc = bf_rt_table_entry_del(l2_table, session, &dev_tgt, 0, key);
    if (rc != BF_SUCCESS) {
        fprintf(stderr, "entry_del failed: %d\n", rc);
        goto err;
    }

    bf_rt_table_key_deallocate(key);
    return 0;

err:
    bf_rt_table_key_deallocate(key);
    return -1;
}

/*
 * update_l2_entry — Single entry point for fail-over integration.
 *
 * When the DiDAQt controller API detects a failure and decides to
 * reroute traffic, it calls this function with the old and new
 * forwarding entries.
 *
 *   old_mac/old_port: the current (failed) path's destination
 *   new_mac/new_port: the replacement path's destination
 */
int update_l2_entry(const uint8_t old_mac[6],
                    const uint8_t new_mac[6], uint32_t new_port)
{
    int rc;

    /* Remove the failed path. */
    rc = del_l2_entry(old_mac);
    if (rc != 0)
        fprintf(stderr, "warning: del old entry failed\n");

    /* Install the replacement path. */
    rc = add_l2_entry(new_mac, new_port);
    if (rc != 0) {
        fprintf(stderr, "error: add new entry failed\n");
        return -1;
    }

    bf_rt_session_complete_operations(session);
    return 0;
}

/* --------------------------------------------------------------- */
/*  Initial configuration from file                                 */
/* --------------------------------------------------------------- */

static int load_config(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror(path);
        return -1;
    }

    char line[256];
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and blank lines. */
        if (line[0] == '#' || line[0] == '\n')
            continue;

        char mac_str[32];
        uint32_t port;
        if (sscanf(line, "%31s %u", mac_str, &port) != 2) {
            fprintf(stderr, "bad config line: %s", line);
            continue;
        }

        uint8_t mac[6];
        if (parse_mac(mac_str, mac) != 0) {
            fprintf(stderr, "bad MAC in config: %s\n", mac_str);
            continue;
        }

        if (add_l2_entry(mac, port) != 0) {
            fprintf(stderr, "failed to add entry: %s -> %u\n",
                    mac_str, port);
        } else {
            printf("  %s -> port %u\n", mac_str, port);
            count++;
        }
    }

    fclose(fp);

    /* Push all updates to hardware. */
    bf_rt_session_complete_operations(session);

    printf("loaded %d forwarding entries\n", count);
    return 0;
}

/* --------------------------------------------------------------- */
/*  Runtime command listener                                        */
/* --------------------------------------------------------------- */

static void handle_command(const char *cmd)
{
    char op[8], mac_str[32];
    uint32_t port;
    uint8_t mac[6];

    if (sscanf(cmd, "%7s %31s %u", op, mac_str, &port) >= 2) {
        if (parse_mac(mac_str, mac) != 0) {
            fprintf(stderr, "bad MAC: %s\n", mac_str);
            return;
        }

        if (strcmp(op, "ADD") == 0) {
            if (add_l2_entry(mac, port) == 0)
                printf("added %s -> port %u\n", mac_str, port);
        } else if (strcmp(op, "MOD") == 0) {
            if (mod_l2_entry(mac, port) == 0)
                printf("modified %s -> port %u\n", mac_str, port);
        } else if (strcmp(op, "DEL") == 0) {
            if (del_l2_entry(mac) == 0)
                printf("deleted %s\n", mac_str);
        } else {
            fprintf(stderr, "unknown command: %s\n", op);
        }

        bf_rt_session_complete_operations(session);
    }
}

static void *cmd_listener(void *arg)
{
    (void)arg;

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("socket"); return NULL; }

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(CMD_PORT);

    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind cmd");
        close(listenfd);
        return NULL;
    }
    listen(listenfd, 4);
    printf("command listener on port %d\n", CMD_PORT);

    while (running) {
        int connfd = accept(listenfd, NULL, NULL);
        if (connfd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        char buf[CMD_BUF_LEN];
        ssize_t n;
        while ((n = recv(connfd, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = '\0';
            /* Process each newline-delimited command. */
            char *saveptr;
            char *line = strtok_r(buf, "\n", &saveptr);
            while (line) {
                handle_command(line);
                line = strtok_r(NULL, "\n", &saveptr);
            }
        }
        close(connfd);
    }

    close(listenfd);
    return NULL;
}

/* --------------------------------------------------------------- */
/*  Main                                                            */
/* --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    /* Initialise BF Runtime and resolve table/field handles. */
    if (bfrt_setup() != 0) {
        fprintf(stderr, "BF Runtime setup failed\n");
        return 1;
    }
    printf("BF Runtime connected to %s\n", P4_PROG_NAME);

    /* Load initial forwarding entries. */
    printf("loading config: %s\n", argv[1]);
    if (load_config(argv[1]) != 0) {
        fprintf(stderr, "config load failed\n");
        return 1;
    }

    /* Start the command listener for runtime updates. */
    pthread_t cmd_thread;
    pthread_create(&cmd_thread, NULL, cmd_listener, NULL);

    /* Main thread waits for termination. */
    while (running)
        sleep(1);

    printf("controller shutting down\n");
    pthread_cancel(cmd_thread);
    pthread_join(cmd_thread, NULL);

    bf_rt_session_destroy(session);
    return 0;
}
