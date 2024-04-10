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
#include "network_helper.h"
#include "constants.h"

unsigned char * make_arp_packet(unsigned char *src_mac, unsigned char *dst_mac, 
        unsigned char *src_ip, unsigned char *tar_ip) {
    if (DEBUG >= 2) {
        printf("Constructing ARP request packet for IP: %s\n",
                get_ip_arr_str(tar_ip));
    }

    // 64 byte packet size
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

    if (DEBUG >= 2) {
        printf("Successfully constructed ARP packet with length: %d bytes\n", 
                total_len);
    }

    return sendbuff;
}

int send_arp_request(int sock_raw, unsigned char *src_mac, 
        unsigned char *src_ip, unsigned char *tar_ip, int dev_index) {
    if (DEBUG >= 2) {
        printf("Sending ARP request for IP: %s\n", get_ip_arr_str(tar_ip));
    }

    unsigned char brd_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char *arp_buff = make_arp_packet(src_mac, brd_mac, src_ip, tar_ip);

    if (arp_buff == NULL) {
        free(arp_buff);

        return -1;
    }

    int snd_len = send_packet(arp_buff, ARP_RQ_PSIZE, sock_raw, dev_index, 
            src_mac);
    if (snd_len < 0)  {
        free(arp_buff);

        return -1;
    }

    free(arp_buff);

    if (DEBUG >= 2) {
        printf("ARP request for IP: %s successfully sent\n", 
                get_ip_arr_str(tar_ip));
    }

    return 0;
}

char * search_arp_table(char *ip_address) {
    if (DEBUG >= 2)
        printf("Searching ARP table for IP address: %s.\n", ip_address);

    const char *COMMAND = "arp -a ";

    const int MAX_PATH = 200;
    char *path = malloc(sizeof(char) * MAX_PATH);
    memset(path, 0, sizeof(char) * MAX_PATH);

    strncpy(path, COMMAND, 100);
    strncat(path, ip_address, 99);

    char **output = load_process(path);

    free(path);

    if (output == NULL) {
        return NULL;
    }

    // Read first line of output
    if (strstr(output[0], "no match found") != NULL) {
        if (DEBUG >= 2) {
            printf("No ARP entry found\n");
        }

        free(output);

        return NULL;
    }

    char *mac_add;
    char *token;
    for (int i = 0; output[i] != NULL; i++) {
        // Tokenise to help parse
        token = strtok(output[i], " ");

        for(int j = 0; token!= NULL; j++) {
            // Parse 3rd token which should be the MAC address
            if (j == 3) {
                if (DEBUG >= 2) {
                    printf("MAC address found: %s\n", token);
                }

                mac_add = token;
                
                free(output);

                return mac_add;
            }

            // Get next token
            token = strtok(NULL, " ");
        }
    }

    free(output);

    return NULL;
}

unsigned char * get_mac_add_from_ip(unsigned char *tar_ip, int sock_raw, 
        unsigned char *src_mac, unsigned char *src_ip, int dev_index, 
        char* dev_name) {
    if (DEBUG >= 2) {
        printf("Attempting to obtain MAC address for IP address %s\n", 
                get_ip_arr_str(tar_ip));
    }

    unsigned char *mac_dest;

    int result = send_arp_request(sock_raw, src_mac, src_ip, tar_ip, dev_index);

    if (result < 0) {
        return NULL;
    }

    // Allow ARP request propagate.
    sleep(2);

    // Now query ARP table.
    char* mac_str = search_arp_table(get_ip_arr_str(tar_ip));

    // If cannot find MAC entry in ARP table.
    if (mac_str == NULL) {
        if (DEBUG >= 2) {
            printf("Cannot get ARP entry for IP address: %s\n", 
                    get_ip_arr_str(tar_ip));
            printf("Obtaining default gateway MAC address\n");
        }

        struct in_addr *gw_ip_add = get_gw_ip_address(dev_name);

        if (gw_ip_add == NULL) {
            return NULL;
        }

        // Recursive call
        mac_dest = get_mac_add_from_ip(get_ip_arr_rep(gw_ip_add), 
                sock_raw, src_mac, src_ip, dev_index, dev_name);

        if (mac_dest == NULL) {
            return NULL;
        }

        if (DEBUG >= 2) {
            printf("Default gateway MAC address obtained\n");
        }
    } else {
        if (DEBUG >= 2) {
            printf("Successfully obtained MAC address from ARP table\n");
        }

        mac_dest = get_mac_from_str(mac_str);

        if (mac_dest == NULL) {
            return NULL;
        }
    }

    return mac_dest;
}