#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "icmp_service.h"
#include "packet_service.h"
#include "constants.h"

int send_icmp_request(const char* src_ip, const char* dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac, 
        int sock_raw, int inter_index) {

    if (DEBUG >= 2) {
        printf("Sending ICMP request for target IP: %s\n", dst_ip);
    }
    
    unsigned char *packet = construct_icmp_packet(src_ip, dst_ip, src_mac, 
            dst_mac);
    
    if (packet == NULL) {
        return -1;
    }
    
    int send_len = send_packet(packet, ICMP_PACK_LENGTH, sock_raw, inter_index,
            src_mac);
    
    if (send_len < 0) {
        return -1;
    }

    if (DEBUG >= 2) {
        printf("ICMP request for target IP: %s sent\n", dst_ip);
    }

    return 0;
}

unsigned char * construct_icmp_packet(const char *src_ip, const char *dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac) {
    if (DEBUG >= 2) {
        printf("Constructing ICMP packet for destination IP: %s\n", dst_ip);
    }

    const int PACKET_SIZE = ICMP_PACK_LENGTH * sizeof(char);

    int total_len = 0;

    unsigned char *sendbuff;
    sendbuff = (unsigned char*)malloc(PACKET_SIZE);
    memset(sendbuff, 0, PACKET_SIZE);

    // Construct the ethernet header
    struct ethhdr *eth = (struct ethhdr *)(sendbuff);

    for (int i = 0; i < MAC_LEN; i++) {
        eth->h_source[i] = src_mac[i];
        eth->h_dest[i] = dst_mac[i];
    }

    eth->h_proto = htons(ETH_P_IP);

    total_len += sizeof(struct ethhdr);

    // Construct the IP header
    struct iphdr *iph = (struct iphdr*)(sendbuff + sizeof(struct ethhdr));

    iph->frag_off = 0x40;           // Don't fragment
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->id = htons(10201);
    iph->ttl = 64;
    iph->protocol = 1;              // ICMP

    iph->daddr = inet_addr(dst_ip);
    iph->saddr = inet_addr(src_ip);

    total_len += sizeof(struct iphdr);

    // Construct ICMP header (8 bytes)
    struct icmphdr *icmph = (struct icmphdr *)((sendbuff + sizeof(struct iphdr))
            + sizeof(struct ethhdr));
    
    icmph->type = ICMP_ECHO;        // ICMP echo request
    icmph->code = 0;
    icmph->checksum = 0;            // Set checksum to 0 as we calculate it

    icmph->un.echo.id = htons(1000);    // Usually pid of sending process
    icmph->un.echo.sequence = htons(0); // 16 bit

    total_len += sizeof(struct icmphdr);

    // Fill remaining fields of IP and TCP headers
    iph->tot_len = htons(total_len - sizeof(struct ethhdr));
    iph->check = ip_checksum((unsigned short *)
            (sendbuff + sizeof(struct ethhdr)));

    icmph->checksum = icmp_checksum((unsigned short *)
            (sendbuff + sizeof(struct ethhdr) + sizeof(struct iphdr)));

    if (DEBUG >= 2) {
        printf("ICMP packet successfully constructed!\n");
    }

    return sendbuff;
}  