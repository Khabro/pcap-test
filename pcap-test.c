#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

// Ethernet Header
typedef struct {
    u_int8_t  ether_dhost[6];
    u_int8_t  ether_shost[6];
    u_int16_t ether_type;
} libnet_ethernet_hdr;

// IPv4 Header
typedef struct {
    u_int8_t ip_hl:4, ip_v:4;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    u_int8_t ip_src[4];
    u_int8_t ip_dst[4];
} libnet_ipv4_hdr;

// TCP Header
typedef struct {
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
    u_int8_t th_off:4, th_x2:4;
    u_int8_t th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
} libnet_tcp_hdr;

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv)) return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        libnet_ethernet_hdr* eth = (libnet_ethernet_hdr*)packet;
        // Check IPv4
        u_int16_t type = ntohs(eth->ether_type);
        if (type != ETHERTYPE_IP)
            continue;

        // IPv4 header loc
        libnet_ipv4_hdr* ip;
        ip = (libnet_ipv4_hdr*)((void*)packet + sizeof(libnet_ethernet_hdr));

       
        int ip_hdr_len = ip->ip_hl;
        ip_hdr_len *= 4;

        // Tcp
        if (ip->ip_p != 0x06)
            continue;

        // TCP header
        libnet_tcp_hdr* tcp;
        tcp = (libnet_tcp_hdr*)((u_char*)ip + ip_hdr_len);

        int tcp_hdr_len = tcp->th_off;
        tcp_hdr_len *= 4;

        // Payload
        const u_char* payload;
        payload = ((const u_char*)tcp) + tcp_hdr_len;

        int payload_len;
        payload_len = ntohs(ip->ip_len) - ip_hdr_len - tcp_hdr_len;
        if (payload_len < 0)
            payload_len = 0;

        int max_len;
        if (payload_len > 20)
            max_len = 20;
        else
            max_len = payload_len;


        printf("\n====== TCP Packet Captured ======\n");
        printf("Src MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

        printf("Dst MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        printf("Src IP   : %d.%d.%d.%d\n",
               ip->ip_src[0], ip->ip_src[1], ip->ip_src[2], ip->ip_src[3]);

        printf("Dst IP   : %d.%d.%d.%d\n",
               ip->ip_dst[0], ip->ip_dst[1], ip->ip_dst[2], ip->ip_dst[3]);

        printf("Src Port : %u\n", ntohs(tcp->th_sport));
        printf("Dst Port : %u\n", ntohs(tcp->th_dport));

        printf("Payload  : ");
        if (max_len == 0) {
            printf("");
        } else {
            for (int i = 0; i < max_len; i++) {
                printf("%02x ", payload[i]);
            }
        }
  

        printf("\n");
    
    }
    pcap_close(pcap);
    return 0;
}

