/*
 * sender.c — Example DAQ data sender
 *
 * Sends a 10 Gbps stream of 1500-byte Ethernet frames over a raw
 * AF_PACKET socket.  Each frame is Ethernet/IPv4/UDP with an 8-byte
 * magic value (SENDER_MAGIC) at the start of the UDP payload,
 * followed by padding to fill the frame.
 *
 * The sender is a "black box" from DiDAQt's perspective (requirement
 * R2) — it has no awareness of the fault-detection framework.
 *
 * Usage:
 *   ./sender <interface> <dst_mac> <sender_id>
 *
 * Example:
 *   ./sender eth0 00:11:22:33:44:55 1
 *
 * Build (on a Linux host with the SDE environment or standalone):
 *   gcc -O2 -Wall -o sender sender.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

/* --------------------------------------------------------------- */
/*  Constants                                                       */
/* --------------------------------------------------------------- */

#define FRAME_LEN      1500            /* Total Ethernet frame size */
#define ETH_HDR_LEN    14
#define IP_HDR_LEN     20
#define UDP_HDR_LEN    8
#define PAYLOAD_LEN    (FRAME_LEN - ETH_HDR_LEN - IP_HDR_LEN - UDP_HDR_LEN)

/* 8-byte magic value written at the start of every UDP payload.
 * Receivers validate this to confirm data integrity.             */
#define SENDER_MAGIC   0xD1DA0754CAFE00AAULL   /* "DiDAQt.CAFE.00AA" */

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* --------------------------------------------------------------- */
/*  Helpers                                                         */
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

/* Minimal IPv4 header checksum. */
static uint16_t ip_checksum(const void *buf, int len)
{
    const uint16_t *p = buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1)    sum += *(const uint8_t *)p;
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

/* Build a complete Ethernet/IPv4/UDP frame template.
 * src/dst IPs are arbitrary — the switches forward on MAC only. */
static void build_frame(uint8_t *frame,
                        const uint8_t src_mac[6],
                        const uint8_t dst_mac[6],
                        uint32_t sender_id)
{
    memset(frame, 0, FRAME_LEN);

    /* --- Ethernet header --- */
    memcpy(frame + 0, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x08; frame[13] = 0x00;   /* EtherType = IPv4 */

    /* --- IPv4 header (20 bytes, no options) --- */
    uint8_t *ip = frame + ETH_HDR_LEN;
    ip[0]  = 0x45;                         /* version + IHL */
    uint16_t ip_total = htons(IP_HDR_LEN + UDP_HDR_LEN + PAYLOAD_LEN);
    memcpy(ip + 2, &ip_total, 2);          /* total length */
    ip[8]  = 64;                           /* TTL */
    ip[9]  = 17;                           /* protocol = UDP */
    /* src IP = 10.0.<sender_id>.1, dst IP = 10.0.<sender_id>.2 */
    ip[12] = 10; ip[13] = 0; ip[14] = (uint8_t)sender_id; ip[15] = 1;
    ip[16] = 10; ip[17] = 0; ip[18] = (uint8_t)sender_id; ip[19] = 2;
    uint16_t cksum = ip_checksum(ip, IP_HDR_LEN);
    memcpy(ip + 10, &cksum, 2);

    /* --- UDP header --- */
    uint8_t *udp = ip + IP_HDR_LEN;
    uint16_t sport = htons(50000);
    uint16_t dport = htons(50000);
    uint16_t udp_len = htons(UDP_HDR_LEN + PAYLOAD_LEN);
    memcpy(udp + 0, &sport, 2);
    memcpy(udp + 2, &dport, 2);
    memcpy(udp + 4, &udp_len, 2);
    /* UDP checksum = 0 (optional for IPv4) */

    /* --- Payload --- */
    uint8_t *payload = udp + UDP_HDR_LEN;
    uint64_t magic = htobe64(SENDER_MAGIC);
    memcpy(payload, &magic, 8);

    /* Remaining payload bytes: fill with sender_id pattern. */
    uint32_t sid_n = htonl(sender_id);
    for (int i = 8; i + 3 < PAYLOAD_LEN; i += 4)
        memcpy(payload + i, &sid_n, 4);
}

/* --------------------------------------------------------------- */
/*  Main                                                            */
/* --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <dst_mac> <sender_id>\n",
                argv[0]);
        return 1;
    }

    const char *ifname    = argv[1];
    const char *dst_mac_s = argv[2];
    uint32_t sender_id    = (uint32_t)atoi(argv[3]);

    uint8_t dst_mac[6];
    if (parse_mac(dst_mac_s, dst_mac) != 0) {
        fprintf(stderr, "Bad MAC format: %s\n", dst_mac_s);
        return 1;
    }

    /* Open raw packet socket. */
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    /* Get interface index and source MAC. */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        return 1;
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sockfd);
        return 1;
    }
    uint8_t src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    /* Bind to the interface. */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    /* Build the frame template (reused for every send). */
    uint8_t frame[FRAME_LEN];
    build_frame(frame, src_mac, dst_mac, sender_id);

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("sender %u: sending %d-byte frames on %s -> %s\n",
           sender_id, FRAME_LEN, ifname, dst_mac_s);

    /* --- Transmit loop --- */
    uint64_t tx_count = 0;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    while (running) {
        ssize_t n = send(sockfd, frame, FRAME_LEN, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("send");
            break;
        }
        tx_count++;

        /* Print rate every ~1 million frames. */
        if ((tx_count & 0xFFFFF) == 0) {
            struct timespec t1;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double elapsed = (t1.tv_sec  - t0.tv_sec)
                           + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
            double gbps = (double)tx_count * FRAME_LEN * 8.0
                        / elapsed / 1e9;
            printf("sender %u: %lu frames, %.2f Gbps\n",
                   sender_id, tx_count, gbps);
        }
    }

    close(sockfd);
    printf("sender %u: stopped after %lu frames\n", sender_id, tx_count);
    return 0;
}
