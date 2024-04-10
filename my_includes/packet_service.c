#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <sys/socket.h>
#include <linux/if_packet.h>

#include "packet_service.h"
#include "network_helper.h"
#include "constants.h"

unsigned short ip_checksum(unsigned short* start_of_header) {
    if (DEBUG >= 2) {
        printf("\n");
        printf("IP Checksum\n");
        printf("-----------\n\n");
        printf("version,ihl,tos:        %d\n", start_of_header[0]);
        printf("tot_len:                %d\n", start_of_header[1]);
        printf("id:                     %d\n", start_of_header[2]);
        printf("frag_off:               %d\n", start_of_header[3]);
        printf("ttl, protocol:          %d\n", start_of_header[4]);
        printf("check:                  %d\n", start_of_header[5]);
        printf("source(1):              %d\n", start_of_header[6]);
        printf("source(2):              %d\n", start_of_header[7]);
        printf("destination(1):         %d\n", start_of_header[8]);
        printf("destination(2):         %d\n", start_of_header[9]);
    }

    unsigned long sum = 0;
    for (int i = 0; i < 10; i++) {
        sum += start_of_header[i];

        // Detect carry
        if (sum > 65545) {
            sum = sum & 0x0000FFFF;
            sum += 1;
        }
    }

    unsigned short result = ~((unsigned short)(sum & 0x0000FFFF));

    if (DEBUG >= 2) {
        printf("IP header checksum:     0x%x\n\n", result);
    }

    return result;
}

unsigned short icmp_checksum(unsigned short* start_of_header) {
    const int NUM_16_WORDS = 4;
    
    if (DEBUG >= 2) {
        printf("ICMP Checksum\n");
        printf("-------------\n\n");
        printf("type,code:              %d\n", start_of_header[0]);
        printf("echo_id,echo_seq:       %d\n", start_of_header[1]);
    }

    unsigned long sum = 0;
    for (int i = 0; i < NUM_16_WORDS; i++) {
        sum += start_of_header[i];

        // Detect carry
        if (sum > 65545) {
            sum = sum & 0x0000FFFF;
            sum += 1;
        }
    }

    unsigned short result = ~((unsigned short)(sum & 0x0000FFFF));

    if (DEBUG >= 2) {
        printf("ICMP header checksum:   0x%x\n\n", result);
    }

    return result;
}

unsigned char * construct_icmp_packet(const char *src_ip, const char *dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac) {
    if (DEBUG >= 2) {
        printf("Constructing ICMP packet for destination IP: %s\n", dst_ip);
    }

    // 64 byte packet size
    const int PACKET_SIZE = 64 * sizeof(char);

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

int send_packet(unsigned char* packet, int packet_len, int socket, 
        int dev_index, unsigned char* mac_src) {
    struct sockaddr_ll sadr_ll;
    sadr_ll.sll_ifindex = dev_index;
    sadr_ll.sll_halen = ETH_ALEN;

    for (int i = 0; i < MAC_LEN; i++) {
        sadr_ll.sll_addr[i] = mac_src[i];
    }

    int send_len = sendto(socket, packet, packet_len, 0, 
            (const struct sockaddr *)&sadr_ll, sizeof(struct sockaddr_ll));
    
    if (send_len < 0) {
        fprintf(stderr, "ERROR: Cannot send packet!\n");

        return -1;
    }

    if (DEBUG >= 1) {
        printf("Packet successfully sent with length: %d bytes\n", send_len);
    }

    return send_len;
}