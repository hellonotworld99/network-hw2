#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MAC_ADDR_LEN 6

typedef struct {
    uint8_t dest[MAC_ADDR_LEN];
    uint8_t src[MAC_ADDR_LEN];
    uint16_t type;
} EthernetHdr;

typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t length;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr src_ip;
    struct in_addr dst_ip;
} IpHdr;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TcpHdr;

void show_usage() {
    printf("Usage: pcap-test <interface>\n");
    printf("Example: pcap-test wlan0\n");
}

bool parse_args(int argc, char *argv[], char **interface) {
    if (argc != 2) {
        show_usage();
        return false;
    }
    *interface = argv[1];
    return true;
}

void print_mac(const uint8_t *mac) {
    for (int i = 0; i < MAC_ADDR_LEN; i++) {
        printf("%02x", mac[i]);
        if (i < MAC_ADDR_LEN - 1) printf(":");
    }
}

void print_ip(struct in_addr ip) {
    printf("%s", inet_ntoa(ip));
}

void process_packet(const struct pcap_pkthdr *header, const uint8_t *data) {
    const EthernetHdr *eth = (const EthernetHdr *)data;
    const IpHdr *ip = (const IpHdr *)(data + sizeof(EthernetHdr));
    const TcpHdr *tcp = (const TcpHdr *)(data + sizeof(EthernetHdr) + ((ip->version_ihl & 0x0F) * 4));

    printf("Ethernet Frame\n");
    printf("   Source MAC: ");
    print_mac(eth->src);
    printf("\n");
    printf("   Destination MAC: ");
    print_mac(eth->dest);
    printf("\n");

    printf("IP Header\n");
    printf("   Source IP: ");
    print_ip(ip->src_ip);
    printf("\n");
    printf("   Destination IP: ");
    print_ip(ip->dst_ip);
    printf("\n");

    printf("TCP Segment\n");
    printf("   Source Port: %d\n", ntohs(tcp->src_port));
    printf("   Destination Port: %d\n", ntohs(tcp->dst_port));

    printf("Payload (Hex): ");
    int ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
    int tcp_hdr_len = (tcp->offset >> 4) * 4;
    int payload_len = header->caplen - (sizeof(EthernetHdr) + ip_hdr_len + tcp_hdr_len);

    if (payload_len > 20) {
        payload_len = 20;
    }

    for (int i = 0; i < payload_len; i++) {
        printf("%02x ", data[sizeof(EthernetHdr) + ip_hdr_len + tcp_hdr_len + i]);
    }
    printf("\n-------------------------------------------\n\n");
}





int main(int argc, char *argv[]) {
    char *interface = NULL;

    if (!parse_args(argc, argv, &interface)) {
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", interface, errbuf);
        return EXIT_FAILURE;
    }

    while (true) {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int result = pcap_next_ex(handle, &header, &packet);
        if (result == 0) continue;
        if (result == PCAP_ERROR || result == PCAP_ERROR_BREAK) {
            fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
        process_packet(header, packet);
    }

    pcap_close(handle);
}
