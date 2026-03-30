/*
 * overhead_traffic_gen.c — Multi-sender raw frame generator
 *
 * Sends a continuous stream of 1500-byte Ethernet frames simulating
 * N senders.  Frame format matches examples/sender.c (Ethernet/IPv4/
 * UDP with SENDER_MAGIC), with sender_id encoded in IP header byte 14.
 *
 * No VLAN tag (for L2Bridge benchmarking).
 *
 * Usage:
 *   sudo ./overhead_traffic_gen <interface> <dst_mac> <num_senders>
 *
 * Runs until SIGTERM/SIGINT, then prints total frame count to stderr.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#define FRAME_LEN      1500
#define ETH_HDR_LEN    14
#define IP_HDR_LEN     20
#define UDP_HDR_LEN    8

#define SENDER_MAGIC   0xD1DA0754CAFE00AAULL

static volatile int running = 1;

static void handle_signal(__attribute__((unused)) int sig) { running = 0; }

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

static void build_frame(uint8_t *frame, const uint8_t src_mac[6],
                        const uint8_t dst_mac[6], uint32_t sender_id)
{
    int payload_len = FRAME_LEN - ETH_HDR_LEN - IP_HDR_LEN - UDP_HDR_LEN;

    memset(frame, 0, FRAME_LEN);

    uint8_t *p = frame;
    memcpy(p, dst_mac, 6); p += 6;
    memcpy(p, src_mac, 6); p += 6;
    p[0] = 0x08; p[1] = 0x00; p += 2;

    uint8_t *ip = p;
    ip[0]  = 0x45;
    uint16_t ip_total = htons(IP_HDR_LEN + UDP_HDR_LEN + payload_len);
    memcpy(ip + 2, &ip_total, 2);
    ip[8]  = 64;
    ip[9]  = 17;
    ip[12] = 10; ip[13] = 0; ip[14] = (uint8_t)sender_id; ip[15] = 1;
    ip[16] = 10; ip[17] = 0; ip[18] = (uint8_t)sender_id; ip[19] = 2;
    uint16_t cksum = ip_checksum(ip, IP_HDR_LEN);
    memcpy(ip + 10, &cksum, 2);

    uint8_t *udp = ip + IP_HDR_LEN;
    uint16_t sport = htons(50000);
    uint16_t dport = htons(50000);
    uint16_t udp_len = htons(UDP_HDR_LEN + payload_len);
    memcpy(udp + 0, &sport, 2);
    memcpy(udp + 2, &dport, 2);
    memcpy(udp + 4, &udp_len, 2);

    uint8_t *payload = udp + UDP_HDR_LEN;
    uint64_t magic = htobe64(SENDER_MAGIC);
    memcpy(payload, &magic, 8);

    uint32_t sid_n = htonl(sender_id);
    for (int i = 8; i + 3 < payload_len; i += 4)
        memcpy(payload + i, &sid_n, 4);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <dst_mac> <num_senders>\n",
                argv[0]);
        return 1;
    }

    const char *ifname    = argv[1];
    const char *dst_mac_s = argv[2];
    int num_senders       = atoi(argv[3]);

    if (num_senders < 1 || num_senders > 255) {
        fprintf(stderr, "num_senders must be 1-255\n");
        return 1;
    }

    uint8_t dst_mac[6];
    if (parse_mac(dst_mac_s, dst_mac) != 0) {
        fprintf(stderr, "Bad MAC format: %s\n", dst_mac_s);
        return 1;
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) { perror("socket"); return 1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX"); close(sockfd); return 1;
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR"); close(sockfd); return 1;
    }
    uint8_t src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); close(sockfd); return 1;
    }

    /* Pre-build frame templates for each sender. */
    uint8_t (*frames)[FRAME_LEN] = malloc(num_senders * FRAME_LEN);
    if (!frames) { perror("malloc"); close(sockfd); return 1; }

    for (int i = 0; i < num_senders; i++)
        build_frame(frames[i], src_mac, dst_mac, (uint32_t)(i + 1));

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    uint64_t tx_count = 0;
    int idx = 0;

    while (running) {
        ssize_t n = send(sockfd, frames[idx], FRAME_LEN, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("send");
            break;
        }
        tx_count++;
        idx++;
        if (idx >= num_senders) idx = 0;
    }

    close(sockfd);
    free(frames);
    fprintf(stderr, "traffic_gen: sent %lu frames for %d senders\n",
            (unsigned long)tx_count, num_senders);
    return 0;
}
