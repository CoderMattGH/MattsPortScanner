#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <errno.h>

#include <time.h>

#include "icmp_service.h"
#include "packet_service.h"
#include "network_helper.h"
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

int ping_target(const unsigned char* src_ip, const unsigned char* dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac, 
        int sock_raw, int inter_index) {
    if (DEBUG >= 2) {
        printf("Pinging target IP: %s\n", get_ip_arr_str(dst_ip));
    }

    // Construct and send ICMP packet
    int icmp_req_val = send_icmp_request(get_ip_arr_str(src_ip), 
            get_ip_arr_str(dst_ip), src_mac, dst_mac, sock_raw, inter_index);
    
    if (icmp_req_val < 0) {
        return -1;
    }
    
    // Wait for ICMP reply
    int icmp_res_val = listen_for_icmp_response(src_mac, src_ip, dst_ip);

    // If timeout occurred
    if (icmp_res_val == 0) {
        return 0;
    }

    // If an error occurred
    if (icmp_res_val == -1) {
        return -1;
    }

    return 1;
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

int listen_for_icmp_response(const unsigned char *loc_mac, 
        const unsigned char *loc_ip, const unsigned char *tar_ip) {
    if (DEBUG >= 2) {
        printf("Listening for ICMP response\n");
    }

    const int PACKET_SIZE = 65536;

    // Construct raw socket and listen to all IPv4 packets
    int icmp_sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    if (icmp_sock_raw < 0) {
        return -1;
    }

    unsigned char *buffer = malloc(PACKET_SIZE * sizeof(char));
    memset(buffer, 0, PACKET_SIZE);

    struct sockaddr saddr;
    int saddr_len = sizeof(struct sockaddr);

    // Sleep time in microseconds (currently 0.1 seconds)
    const int SLEEP_TIME_MICS = 1000 * 1000 * 0.1;

    // Timeout in seconds
    const int TIMEOUT_SECS = 7;             

    long int start_time = time(0);
    long int curr_time = time(0);
    while ((curr_time - start_time) <= TIMEOUT_SECS) {
        // Clear errno
        errno = 0;

        // Get current time
        curr_time = time(0);        

        // Receive a network packet and copy into buffer (Non-blocking)
        int buff_len = recvfrom(icmp_sock_raw, buffer, PACKET_SIZE, MSG_DONTWAIT,
                &saddr, (socklen_t *)&saddr_len);

        if (buff_len == -1) {
            // Would block
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(SLEEP_TIME_MICS);

                continue;
            } else {
                // An error occurred
                close(icmp_sock_raw);
                free(buffer);

                return -1;
            }
        }

        // Extract ethernet header
        struct ethhdr *eth = (struct ethhdr *)(buffer);

        if (DEBUG >= 3) {
            printf("Packet received: ");
            printf("src_mac: %s", get_mac_str(eth->h_source));
            printf("dst_mac: %s\n", get_mac_str(eth->h_dest));
        }

        // Check MAC source address matches local interface
        if (compare_mac_add(loc_mac, eth->h_dest) != 0) {
            continue;
        }

        // Extract IP header
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

        // Filter ICMP packets (Protocol 0x01)
        if (iph->protocol != 0x01) {
            continue;
        }

        unsigned char* ip_src_pack = get_ip_32_arr(iph->saddr);
        unsigned char* ip_dst_pack = get_ip_32_arr(iph->daddr);

        if (DEBUG >= 2) {
            printf("ICMP packet: ");
            printf("src_ip: %s ", get_ip_arr_str(ip_src_pack));
            printf("dst_ip: %s\n", get_ip_arr_str(ip_dst_pack));
        }

        // Check that ICMP response is from the target
        if ((compare_ip_add(loc_ip, ip_dst_pack) != 0) || 
                (compare_ip_add(tar_ip, ip_src_pack) != 0)) {
            continue;
        }

        if (DEBUG >= 2) {
            printf("Target ICMP request received\n");
        }

        close(icmp_sock_raw);

        return 1;
    }

    if (DEBUG >= 2) {
        printf("Timeout occurred whilst waiting for ICMP response.\n");
    }

    close(icmp_sock_raw);

    return 0;
}