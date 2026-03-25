/*
 * sender.c — Example DAQ data sender
 *
 * Sends a 10 Gbps stream of 1500-byte Ethernet frames over a raw
 * AF_PACKET socket.  Each frame is Ethernet/802.1Q/IPv4/UDP with an
 * 8-byte magic value (SENDER_MAGIC) at the start of the UDP payload,
 * followed by padding to fill the frame.
 *
 * When vlan_id is 0, frames are sent without a VLAN tag and the full
 * 1458-byte payload is available.  When vlan_id > 0, the 4-byte
 * 802.1Q header is included and the payload shrinks to 1454 bytes
 * so the total frame stays at 1500.
 *
 * The sender is a "black box" from DiDAQt's perspective (requirement
 * R2) — it has no awareness of the fault-detection framework.
 *
 * Flags:
 *   -f    Faulty mode: alternate between valid and invalid magic
 *         values every packet, simulating intermittent data corruption.
 *
 * Usage:
 *   ./sender [-f] <interface> <dst_mac> <sender_id> [vlan_id]
 *
 * Example:
 *   ./sender eth0 00:11:22:33:44:55 1 100
 *   ./sender -f eth0 00:11:22:33:44:55 1 100
 *
 * Build (on a Linux host):
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
#define VLAN_HDR_LEN   4
#define IP_HDR_LEN     20
#define UDP_HDR_LEN    8

/* 8-byte magic value written at the start of every UDP payload.
 * Receivers validate this to confirm data integrity.             */
#define SENDER_MAGIC       0xD1DA0754CAFE00AAULL   /* "DiDAQt.CAFE.00AA" */
#define SENDER_MAGIC_BAD   0xDEADBEEFDEADBEEFULL   /* intentionally wrong */

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

/*
 * Build a complete Ethernet(/VLAN)/IPv4/UDP frame template.
 * src/dst IPs are arbitrary — the switches forward on MAC only.
 *
 * Returns the actual frame length written (always FRAME_LEN).
 */
static int build_frame(uint8_t *frame,
                       const uint8_t src_mac[6],
                       const uint8_t dst_mac[6],
                       uint32_t sender_id,
                       uint16_t vlan_id)
{
    int use_vlan = (vlan_id > 0);
    int l2_len   = ETH_HDR_LEN + (use_vlan ? VLAN_HDR_LEN : 0);
    int payload_len = FRAME_LEN - l2_len - IP_HDR_LEN - UDP_HDR_LEN;

    memset(frame, 0, FRAME_LEN);

    /* --- Ethernet header --- */
    uint8_t *p = frame;
    memcpy(p, dst_mac, 6);  p += 6;
    memcpy(p, src_mac, 6);  p += 6;

    if (use_vlan) {
        /* 802.1Q: TPID + TCI */
        p[0] = 0x81; p[1] = 0x00;  p += 2;         /* TPID */
        uint16_t tci = htons(vlan_id & 0x0FFF);
        memcpy(p, &tci, 2);        p += 2;          /* TCI  */
    }

    /* EtherType = IPv4 */
    p[0] = 0x08; p[1] = 0x00;  p += 2;

    /* --- IPv4 header (20 bytes, no options) --- */
    uint8_t *ip = p;
    ip[0]  = 0x45;                                   /* version + IHL */
    uint16_t ip_total = htons(IP_HDR_LEN + UDP_HDR_LEN + payload_len);
    memcpy(ip + 2, &ip_total, 2);                    /* total length  */
    ip[8]  = 64;                                     /* TTL           */
    ip[9]  = 17;                                     /* protocol=UDP  */
    /* src IP = 10.0.<sender_id>.1, dst IP = 10.0.<sender_id>.2 */
    ip[12] = 10; ip[13] = 0; ip[14] = (uint8_t)sender_id; ip[15] = 1;
    ip[16] = 10; ip[17] = 0; ip[18] = (uint8_t)sender_id; ip[19] = 2;
    uint16_t cksum = ip_checksum(ip, IP_HDR_LEN);
    memcpy(ip + 10, &cksum, 2);

    /* --- UDP header --- */
    uint8_t *udp = ip + IP_HDR_LEN;
    uint16_t sport = htons(50000);
    uint16_t dport = htons(50000);
    uint16_t udp_len = htons(UDP_HDR_LEN + payload_len);
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
    for (int i = 8; i + 3 < payload_len; i += 4)
        memcpy(payload + i, &sid_n, 4);

    return FRAME_LEN;
}

/* --------------------------------------------------------------- */
/*  Main                                                            */
/* --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    /* Parse optional -f flag. */
    int faulty = 0;
    if (argc > 1 && strcmp(argv[1], "-f") == 0) {
        faulty = 1;
        argv++;
        argc--;
    }

    if (argc < 4 || argc > 5) {
        fprintf(stderr,
                "Usage: %s [-f] <interface> <dst_mac> <sender_id> [vlan_id]\n",
                argv[0]);
        return 1;
    }

    const char *ifname    = argv[1];
    const char *dst_mac_s = argv[2];
    uint32_t sender_id    = (uint32_t)atoi(argv[3]);
    uint16_t vlan_id      = (argc == 5) ? (uint16_t)atoi(argv[4]) : 0;

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

    /* Build frame templates. */
    uint8_t frame_good[FRAME_LEN];
    uint8_t frame_bad[FRAME_LEN];
    build_frame(frame_good, src_mac, dst_mac, sender_id, vlan_id);

    if (faulty) {
        /* Build a second template with an invalid magic value. */
        memcpy(frame_bad, frame_good, FRAME_LEN);
        int use_vlan = (vlan_id > 0);
        int l2_len   = ETH_HDR_LEN + (use_vlan ? VLAN_HDR_LEN : 0);
        int magic_off = l2_len + IP_HDR_LEN + UDP_HDR_LEN;
        uint64_t bad = htobe64(SENDER_MAGIC_BAD);
        memcpy(frame_bad + magic_off, &bad, 8);
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("sender %u: sending %d-byte frames on %s -> %s (vlan %u)%s\n",
           sender_id, FRAME_LEN, ifname, dst_mac_s, vlan_id,
           faulty ? " [FAULTY]" : "");

    /* --- Transmit loop --- */
    uint64_t tx_count = 0;

    while (running) {
        uint8_t *frame = (faulty && (tx_count & 1))
                       ? frame_bad : frame_good;
        ssize_t n = send(sockfd, frame, FRAME_LEN, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("send");
            break;
        }
        tx_count++;
    }

    close(sockfd);
    printf("sender %u: stopped after %lu frames\n", sender_id, tx_count);
    return 0;
}
