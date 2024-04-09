#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <net/if_arp.h>

#include "arp_service.h"
#include "packet_service.h"
#include "constants.h"

/*
 * Constructs an ARP packet with the supplied parameters.
 */
unsigned char * make_arp_packet(unsigned char *src_mac, unsigned char *dst_mac, 
        unsigned char *src_ip, unsigned char *tar_ip) {
    // Minimum size ethernet frame is 64
    const int PACKET_SIZE = ARP_RQ_PSIZE * sizeof(char);

    int total_len = 0;

    unsigned char *sendbuff;
    sendbuff = malloc(PACKET_SIZE);

    // Construct the ethernet header
    struct ethhdr *eth = (struct ethhdr *)(sendbuff);

    // Fill source and destination mac addresses
    for (int i = 0; i < MAC_LEN; i++) {
        eth->h_source[i] = src_mac[i];
        eth->h_dest[i] = dst_mac[i];
    }

    eth->h_proto = htons(ETH_P_ARP);

    total_len += sizeof(struct ethhdr);

    // Construct the ARP header
    struct arphdr *arp = (struct arphdr *)(sendbuff + sizeof(struct ethhdr));

    arp->ar_hrd = htons(ARPHRD_ETHER);
    arp->ar_pro = htons(ETH_P_IP);      // IPv4
    arp->ar_hln = 6;                    // Link-layer address size
    arp->ar_pln = 4;                    // Protocol size
    arp->ar_op = htons(ARPOP_REQUEST);  // ARP op-code (request)

    total_len += sizeof(struct arphdr);

    // Construct the ARP payload
    struct arp_payload {
        unsigned char src_mac[MAC_LEN];
        unsigned char src_ip[IP_LEN];
        unsigned char tar_mac[MAC_LEN];
        unsigned char tar_ip[IP_LEN];
    };

    struct arp_payload *payload = (struct arp_payload *)
            (sendbuff + sizeof(struct ethhdr) + sizeof(struct arphdr));
    
    for (int i = 0; i < IP_LEN; i++) {
        payload->src_ip[i] = src_ip[i];
        payload->tar_ip[i] = tar_ip[i];
    }

    for (int i = 0; i < MAC_LEN; i++) {
        payload->src_mac[i] = src_mac[i];
        payload->tar_mac[i] = 0x00;         // All zeros for ARP request
    }

    total_len += sizeof(struct arp_payload);

    printf("ARP packet TOTAL LEN: %d\n", total_len);

    return sendbuff;
}

int send_arp_request(int sock_raw, unsigned char *src_mac, 
        unsigned char *src_ip, unsigned char *tar_ip, int dev_index) {
    printf("Sending ARP request!\n");

    unsigned char brd_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char *arp_buff = make_arp_packet(src_mac, brd_mac, src_ip, tar_ip);

    if (arp_buff == NULL) {
        return -1;
    }

    int snd_len = send_packet(arp_buff, ARP_RQ_PSIZE, sock_raw, dev_index, 
            src_mac);
    if (snd_len < 0)  {
        return -1;
    }

    return 0;
}