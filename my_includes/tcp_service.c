#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include "tcp_service.h"
#include "checksum_service.h"
#include "packet_service.h"
#include "network_helper.h"
#include "constants.h"

unsigned char * construct_syn_packet(const char *src_ip, const char *dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac, 
        unsigned short int src_port, unsigned short int dst_port) {
    if (DEBUG >= 3) {
        printf("Constructing SYN TCP/IP packet for destination IP: %s\n",
                get_ip_arr_str(dst_ip));
    }

    const int PACKET_SIZE = 64;

    int total_len = 0;

    unsigned char *sendbuff;
    sendbuff = malloc(PACKET_SIZE * sizeof(char));
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

    iph->frag_off = 0x40;               // Don't fragment
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->id = htons(10201);
    iph->ttl = 64;
    iph->protocol = 6;                  // TCP

    iph->daddr = inet_addr(dst_ip);
    iph->saddr = inet_addr(src_ip);

    total_len += sizeof(struct iphdr);

    // Construct TCP header (8 bytes)
    struct tcphdr *th = (struct tcphdr *)(sendbuff + sizeof(struct ethhdr)
            + sizeof(struct iphdr));
    
    th->source = htons(src_port);
    th->dest = htons(dst_port);
    th->seq = htons(0);
    th->fin = 0;
    th->syn = 1;
    th->rst = 0;
    th->psh = 0;
    th->ack = 0;
    th->urg = 0;
    th->window = htons (5840);          // Maximum allowed window size
    th->check = 0;                      // Leave checksum at 0 for now
    th->urg_ptr = 0;

    total_len += sizeof(struct tcphdr);

    // Fill the remaining fields of IP and TCP headers
    th->doff = (unsigned char)5;
    iph->tot_len = htons(total_len - sizeof(struct ethhdr));

    // Checksum
    iph->check = ip_checksum((unsigned short int *)iph);
    
    // Construct TCP Pseuodoheader
    struct psheader *psh = malloc(sizeof(struct psheader));
    memset(psh, 0, sizeof(struct psheader));

    psh->saddr = iph->saddr;
    psh->daddr = iph->daddr;
    psh->reserved = 0;
    psh->protocol = iph->protocol;
    psh->tcpseglen = htons(20);

    // Calculate TCP checksum
    unsigned short tcp_sum = tcp_checksum((short unsigned int *)th, 
            (short unsigned int *)psh);
    
    th->check = tcp_sum;

    return sendbuff;
}

unsigned short int * listen_for_ACK_replies(const unsigned char* tar_ip, 
        const unsigned char* dest_mac) {
    if (DEBUG >= 2) {
        printf("Listening to ACK replies from target IP: %s\n", 
                get_ip_arr_str(tar_ip));
    }

    // Temporary array to hold open port numbers.
    unsigned short int open_ports[MAX_PORT] = {0};
    
    int sock_listen_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    //int sock_listen_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_listen_raw < 0) {
        fprintf(stderr, "ERROR: Cannot open raw socket!\n");

        errno = EIO;

        return NULL;
    }

    // Receive a network packet and copy it in to buffer.
    const int MAX_R_BUFF_SZ = 65535;

    unsigned char *rec_buff = malloc(sizeof(char) * MAX_R_BUFF_SZ);

    struct sockaddr saddr;
    int saddr_len = sizeof(struct sockaddr);

    int array_index = 0;
    while (1) {
        // Reset buffer
        memset(rec_buff, 0, MAX_R_BUFF_SZ);

        int buf_len = recvfrom(sock_listen_raw, rec_buff, MAX_R_BUFF_SZ, 0, 
                &saddr, (socklen_t *)&saddr_len);

        // Extract ethernet header
        struct ethhdr *eth = (struct ethhdr *)(rec_buff);

        unsigned char rec_mac_des[MAC_LEN];
        for (int i = 0; i < MAC_LEN; i++) {
            rec_mac_des[i] = eth->h_dest[i];
        }

        // Packet was not addressed to this interface
        if (compare_mac_add(rec_mac_des, dest_mac) != 0) {
            continue;
        }
        
        // Extract IP header
        struct iphdr *iph = (struct iphdr *)
                (rec_buff + sizeof(struct ethhdr));

        if (DEBUG >= 3) {
            printf("IP packet received: ");
            printf("src: %s ", get_ip_32_str(iph->saddr));
            printf("proto: %d\n", iph->protocol);
        }

        // Packet was not from target IP address and was not TCP
        if ((compare_ip_add(get_ip_32_arr(iph->saddr), tar_ip) != 0) ||
                (iph->protocol != 6)) {
            continue;
        }

        // Extract TCP header
        struct tcphdr *th = (struct tcphdr *)(rec_buff + 
                sizeof(struct ethhdr) + sizeof(struct iphdr));

        // Check that packet was an ACK with no RESET flag
        if ((th->ack != 1) || th->rst == 1) {
            continue;
        }

        if (DEBUG >= 2) {
            printf("Open TCP port detected: %d\n", htons(th->source));
        }

        open_ports[array_index++] = htons(th->source);
    }

    // Find real length of open_ports array
    int open_ports_len = 0;
    for (open_ports_len; open_ports[open_ports_len] != 0; open_ports_len++) {}
    open_ports_len++;

    // No open ports found
    if (open_ports_len == 0) {
        return NULL;
    }

    // Copy open ports to new malloced array
    unsigned short int *open_ports_perm = 
            malloc(sizeof(short int) * open_ports_len);
    memset(open_ports_perm, 0, sizeof(short int) * open_ports_len);

    // Transfer values
    for (int i = 0; i < open_ports_len; i++) {
        open_ports_perm[i] = open_ports[i];
    }

    return open_ports_perm;
}