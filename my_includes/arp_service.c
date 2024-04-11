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

#include <errno.h>
#include <time.h>

#include "arp_service.h"
#include "packet_service.h"
#include "network_helper.h"
#include "process_service.h"
#include "constants.h"

unsigned char * make_arp_packet(const unsigned char *src_mac, 
        const unsigned char *dst_mac, const unsigned char *src_ip, 
        const unsigned char *tar_ip) {
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

int send_arp_request(int sock_raw, const unsigned char *src_mac, 
        const unsigned char *src_ip, const unsigned char *tar_ip, 
        int dev_index) {
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

char * search_arp_table(const char *ip_address) {
    if (DEBUG >= 2)
        printf("Searching ARP table for IP address: %s\n", ip_address);

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

unsigned char * get_mac_add_from_ip(const unsigned char *tar_ip, int sock_raw, 
        const unsigned char *src_mac, const unsigned char *src_ip, 
        int dev_index, const char* dev_name) {
    if (DEBUG >= 2) {
        printf("Attempting to obtain MAC address for IP address %s\n", 
                get_ip_arr_str(tar_ip));
    }

    unsigned char *mac_dest;

    int result = send_arp_request(sock_raw, src_mac, src_ip, tar_ip, dev_index);

    if (result < 0) {
        return NULL;
    }

    mac_dest = listen_for_arp_response(src_mac, src_ip, tar_ip);

    // If no ARP response detected, check ARP table just in case we have a 
    // cached entry.
    if (mac_dest == NULL) {
        char *mac_str = search_arp_table(get_ip_arr_str(tar_ip));

        if (mac_str != NULL) {
            mac_dest = get_mac_from_str(mac_str);
        }
    }

    // If cannot find MAC entry in ARP table.
    if (mac_dest == NULL) {
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

        printf("TEMPMAC: %x:%x:%x\n", mac_dest[0], mac_dest[1], mac_dest[2]);
    } else {
        if (DEBUG >= 2) {
            printf("Successfully obtained MAC address\n");
        }
    }

    return mac_dest;
}

unsigned char * listen_for_arp_response(const unsigned char *loc_mac, 
        const unsigned char *loc_ip, const unsigned char *tar_ip) {
    if (DEBUG >= 2) {
        printf("Listening for ARP response\n");
    }

    const int PACKET_SIZE = 65536;

    // Construct raw socket and listen to all ARP packets
    int arp_sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (arp_sock_raw < 0) {
        return NULL;
    }

    unsigned char *buffer = malloc(PACKET_SIZE * sizeof(char));
    memset(buffer, 0, PACKET_SIZE * sizeof(char));

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

        // Receive a network packet and copy it into buffer (Non-blocking)
        int buff_len = recvfrom(arp_sock_raw, buffer, PACKET_SIZE, MSG_DONTWAIT, 
                &saddr, (socklen_t *)&saddr_len);
        
        if (buff_len == -1) {
            // Would block
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(SLEEP_TIME_MICS);

                continue;
            } else {
                // An error occurred
                close(arp_sock_raw);
                free(buffer);

                return NULL;
            }
        }

        // Extract ethernet header
        struct ethhdr *eth = (struct ethhdr *)(buffer);

        if (DEBUG >= 2) {
            printf("ARP packet received: ");
            printf("src_mac: %s ", get_mac_str(eth->h_source));
            printf("dst_mac: %s\n", get_mac_str(eth->h_dest));
        }

        // Check MAC source address matches local interface
        if (compare_mac_add(loc_mac, eth->h_dest) != 0) {
            continue;
        }

        // Extract ARP header
        struct arphdr *arph = (struct arphdr *)(buffer + sizeof(struct ethhdr));

        if (DEBUG >= 2) {
            printf("ARP packet: ");
            printf("op-code: %d\n", htons(arph->ar_op));
        }

        // Extract data payload
        struct arp_payload *arppl = (struct arp_payload *)
                (buffer + sizeof(struct ethhdr) + sizeof(struct arphdr));
        
        if (DEBUG >= 2) {
            printf("ARP payload: ");
            printf("src_ip: %s ", get_ip_arr_str(arppl->src_ip));
            printf("dst_ip: %s ", get_ip_arr_str(arppl->tar_ip));
            printf("src_mac: %s ", get_mac_str(arppl->src_mac));
            printf("dst_mac: %s\n", get_mac_str(arppl->tar_mac));
        }

        // Check that payload contains target MAC address
        if ((compare_ip_add(tar_ip, arppl->src_ip) != 0) || 
                (compare_ip_add(loc_ip, arppl->tar_ip) != 0) ||
                (compare_mac_add(loc_mac, arppl->tar_mac) != 0)) {
            continue;
        }
    
        if (DEBUG >= 2) {
            printf("Correct ARP reply verified\n");
        }

        close(arp_sock_raw);

        // Copy MAC address of target to new buffer
        unsigned char *mac_tar = malloc(sizeof(char) * MAC_LEN);
        memset(mac_tar, 0, sizeof(char) * MAC_LEN);

        for (int i = 0; i < MAC_LEN; i++) {
            mac_tar[i] = arppl->src_mac[i];
        }

        free(buffer);

        if (DEBUG >= 2) {
            printf("Target MAC address: %s\n", get_mac_str(mac_tar));
        }

        return mac_tar;
    }

    close(arp_sock_raw);
    free (buffer);

    if (DEBUG >= 2) {
        printf("Timeout occurred whilst waiting for ARP reply.\n");
    }

    return NULL;
}