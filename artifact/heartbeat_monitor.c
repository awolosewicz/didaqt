/*
 * heartbeat_monitor.c — Controller-side heartbeat receiver
 *
 * Listens for DiDAQt heartbeat UDP packets from receivers and prints
 * a live status display showing which senders each receiver reports
 * as healthy.
 *
 * Usage:
 *   ./heartbeat_monitor <port>
 *
 * Example:
 *   ./heartbeat_monitor 9000
 *
 * Build:
 *   gcc -O2 -Wall -o heartbeat_monitor heartbeat_monitor.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_SENDERS 256

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    uint16_t port = (uint16_t)atoi(argv[1]);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("heartbeat monitor listening on UDP port %u\n", port);

    /*
     * Heartbeat wire format (network byte order):
     *   uint32_t  receiver_id
     *   uint16_t  sender_count
     *   uint32_t  sender_ids[sender_count]
     */
    uint8_t buf[6 + MAX_SENDERS * 4];
    uint64_t hb_count = 0;

    while (running) {
        struct sockaddr_in src;
        socklen_t src_len = sizeof(src);

        ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &src_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }

        /* Need at least receiver_id + sender_count. */
        if (n < 6)
            continue;

        uint32_t receiver_id;
        uint16_t sender_count;
        memcpy(&receiver_id,  buf,     4);
        memcpy(&sender_count, buf + 4, 2);
        receiver_id  = ntohl(receiver_id);
        sender_count = ntohs(sender_count);

        /* Validate packet size. */
        if (n < 6 + (ssize_t)sender_count * 4)
            continue;

        hb_count++;

        /* Build sender list string. */
        char senders_str[1024];
        int  pos = 0;
        for (int i = 0; i < sender_count && pos < 1000; i++) {
            uint32_t sid;
            memcpy(&sid, buf + 6 + i * 4, 4);
            sid = ntohl(sid);
            if (i > 0) pos += snprintf(senders_str + pos, 1024 - pos, ", ");
            pos += snprintf(senders_str + pos, 1024 - pos, "%u", sid);
        }
        if (sender_count == 0)
            snprintf(senders_str, sizeof(senders_str), "(none)");

        /* Get timestamp. */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct tm *tm = localtime(&ts.tv_sec);
        char timestr[32];
        strftime(timestr, sizeof(timestr), "%H:%M:%S", tm);

        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, src_ip, sizeof(src_ip));

        printf("[%s.%03ld] HB #%lu from %s | receiver %u: "
               "%u sender(s) healthy: [%s]\n",
               timestr, ts.tv_nsec / 1000000, hb_count,
               src_ip, receiver_id, sender_count, senders_str);
    }

    close(sockfd);
    printf("heartbeat monitor stopped after %lu heartbeats\n", hb_count);
    return 0;
}
