#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <net/ethernet.h>

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <time.h>

#include "my_includes/network_helper.h"

#ifndef DEBUG
    #define DEBUG 1
#endif

#define MAX_PORT 65535
#define MAC_LEN 6
#define IP_LEN 4

unsigned char * construct_icmp_packet(const char *src_ip, const char *dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac);

unsigned short ip_checksum(unsigned short* start_of_header);

unsigned short icmp_checksum(unsigned short* start_of_header);

int send_packet(unsigned char* packet, int packet_len, int socket, 
        int dev_index, unsigned char* mac_src);

struct in_addr * get_gw_ip_address(char *dev_name);

char * ip_to_mac(char *ip_address);

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("usage: mps <destination_ip> <interface_name>\n");

        return 0;
    }

    printf("===================\n");
    printf("Matt's Port Scanner\n");
    printf("===================\n\n");

    struct in_addr *dest_ip;
    unsigned short start_prt = 1;
    unsigned short end_prt = MAX_PORT;
    char *dev_name;
    unsigned char *mac_dest;
    
    int loc_int_index;                      // Local interface index
    unsigned char *loc_mac_add;             // Local MAC address
    struct in_addr *loc_ip_add;             // Local IP address

    // Set destination IP
    dest_ip = get_ip_from_str(argv[1]);

    // Set network interface ID
    dev_name = argv[2];

    if (dest_ip == NULL) {
        fprintf(stderr, "ERROR: Cannot parse IP address\n");

        return -1;
    }

    // Search the ARP table for the MAC address associated with dest_ip.
    char* mac_str = ip_to_mac(get_ip_str(dest_ip));

    if (mac_str == NULL) {
        printf("Cannot get ARP entry for IP address: %s\n", get_ip_str(dest_ip));
        printf("Setting MAC_ADDRESS to gateway address.\n");
        struct in_addr *gw_ip_add = get_gw_ip_address(dev_name);

        if(gw_ip_add == NULL) {
            fprintf(stderr, "ERROR: Unable to get destination MAC address.\n");

            return -1;
        }

        char* gw_ip_str = get_ip_str(gw_ip_add);
        if (gw_ip_str == NULL) {
            fprintf(stderr, 
                    "ERROR: Unable to convert IP address into string.\n");
        }

        char *temp = ip_to_mac(gw_ip_str);
        mac_dest = get_mac_from_str(temp);

        if (mac_dest == NULL) {
            fprintf(stderr, "ERROR: Unable to get destination MAC address.\n");

            return -1;
        }
    } else {
        mac_dest = get_mac_from_str(mac_str);
    }

    // Verbose tag
    printf("Information\n");
    printf("-----------\n\n");
    printf("Destination IP:             %s\n", get_ip_str(dest_ip));
    printf("Destination ports:          %d-%d\n", start_prt, end_prt);
    printf("Destination MAC address:    %s\n", get_mac_str(mac_dest));
    printf("Local network device:       %s\n", "enp4s0");

    int sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if(sock_raw == -1) {
        fprintf(stderr, "ERROR: Cannot open raw socket!\n");

        return -1;
    }

    // Get interface index
    loc_int_index = get_interface_index(&sock_raw, dev_name);
    if (loc_int_index == -1) {
        fprintf(stderr, "ERROR: Cannot get interface index.\n");

        return -1;
    }

    // Get MAC address of the interface
    loc_mac_add = get_mac_address(&sock_raw, dev_name);
    if (loc_mac_add == NULL) {
        fprintf(stderr, "ERROR: Cannot get MAC address.\n");

        return -1;
    }

    // Get IP address of the interface
    loc_ip_add = get_ip_address(&sock_raw, dev_name);
    if (loc_ip_add == NULL) {
        fprintf(stderr, "ERROR: Cannot get IP address.\n");

        return -1;
    }

    printf("Local device index:         %d\n", loc_int_index);
    printf("Local MAC address:          %s\n", get_mac_str(loc_mac_add));
    printf("Local IP address:           %s\n\n", get_ip_str(loc_ip_add));

    unsigned char *packet = construct_icmp_packet(get_ip_str(loc_ip_add), 
            get_ip_str(dest_ip), loc_mac_add, mac_dest);

    int send_len = send_packet(packet, 64, sock_raw, loc_int_index, 
            loc_mac_add);

    if (send_len < 0) {
        fprintf(stderr, "ERROR: problem sending packet!\n");

        return -1;
    }

    close(sock_raw);

    printf("Socket closed!\n");
    printf("Exiting!\n");

    return 0;
}

/*
 * Attempts to send a supplied packet using the supplied parameters.
 * Returns -1 on error otherwise returned the length in bytes sent.
 */
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
        printf("Packet successfully sent with length: %d bytes!\n\n", send_len);
    }

    return send_len;
}

// Data segment on icmp send is optional
unsigned char * construct_icmp_packet(const char *src_ip, const char *dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac) {
    // Minimum size ethernet frame is 64
    const int PACKET_SIZE = 64 * sizeof(char);

    int total_len = 0;

    unsigned char *sendbuff;
    sendbuff = (unsigned char*)malloc(PACKET_SIZE);
    memset(sendbuff, 0, PACKET_SIZE);

    // Construct the ethernet header
    struct ethhdr *eth = (struct ethhdr *)(sendbuff);

    for (int i = 0; i < 6; i++) {
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

    return sendbuff;
}   

/*
 * Calculates the IP header checksum and returns the result.
 * Checksum is the 16 bit ones complement of the sum of all 16 bit words in the
 * IP header.
 * Takes as a parameter a pointer to the start of the IP header.
 */
unsigned short ip_checksum(unsigned short* start_of_header) {
    if (DEBUG >= 2) {
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
        printf("IP header checksum: 0x%x\n\n", result);
    }

    return result;
}

/*
 * Calculates the ICMP header checksum and returns the result.
 * Checksum is the 16 bit ones complement of the sum of all 16 bit words in the
 * ICMP header.
 * Header length is 8 bytes without any payload data.
 * Takes as a parameter a pointer to the start of the ICMP header.
 * NOTE: Any payload data should be included in the sum.
 */
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
        printf("ICMP header checksum: 0x%x\n\n", result);
    }

    return result;
}

/*
 * Returns the gateway of the IP address. 
 * Returns NULL on error.
 */
struct in_addr * get_gw_ip_address(char *dev_name) {
    printf("Trying to find IP address of default gateway!\n");

    FILE *fp;
    const char* path = "route -n | grep ";
    
    const int P_BUFF_SIZE = sizeof(char) * 100;
    char* path_buff = malloc(P_BUFF_SIZE);
    memset(path_buff, 0, P_BUFF_SIZE);
    strncpy(path_buff, path, strlen(path));
    strncat(path_buff, dev_name, P_BUFF_SIZE - 1 - strlen(path_buff));

    fp = popen(path_buff, "r");

    const int OUTPUT_SIZE = sizeof(char) * 100;
    char *output = malloc(OUTPUT_SIZE);
    memset(output, 0, OUTPUT_SIZE);

    char *retVal;
    char *token;
    while((retVal = fgets(output, OUTPUT_SIZE, fp)) != NULL) {
        printf("OUTPUT: %s\n", output);
        
        // Parse output
        token = strtok(output, " ");
        for (int i = 0; token != NULL; i++) {
            if(strcmp("0.0.0.0", token) == 0) {
                printf("Gateway row obtained!\n");
                token = strtok(NULL, " ");
                
                // ERROR: Could not obtain IP address for default gateway
                if (token == NULL)
                    return NULL;
                
                struct in_addr *ip_add = get_ip_from_str(token);

                if (ip_add == NULL)
                    return NULL;

                // Default gateway IP address found!
                printf("Default gateway IP found: %s!\n", get_ip_str(ip_add));

                return ip_add;
            } else {
                token = strtok(NULL, " ");
            }
        }
    }

    return NULL;
}

/* 
 * Queries the ARP table to get the assigned MAC address of the IP.
 * Note that if the IP address is not found in the table, then the
 * gateway address is returned.
 * Returns NULL if entry in ARP table cannot be found or error.
*/
char * ip_to_mac(char *ip_address) {
    if (DEBUG > 1)
        printf("Searching ARP table for IP address: %s.\n", ip_address);

    const char *COMMAND = "arp -a ";

    FILE *fp;
    const int MAX_PATH = 200;
    char *path = malloc(sizeof(char) * MAX_PATH);
    memset(path, 0, sizeof(char) * MAX_PATH);

    strncpy(path, COMMAND, MAX_PATH - 1);
    strncat(path, ip_address, (MAX_PATH - 1) - strlen(path));

    fp = popen(path, "r");

    char* output = malloc(sizeof(char) * 100);
    memset(output, 0, sizeof(char) * 100);
    
    char *retVal = fgets(output, sizeof(char) * 100, fp);
    if (retVal == NULL) {
        return NULL;
    }

    // Check if arp entry exists
    if (strstr(output, "no match found") != NULL) {
        printf("No ARP entry found!\n");

        return NULL;
    }

    char *token;
    token = strtok(output, " ");

    const int MAX_TOKENS = 10;
    char *tokens[MAX_TOKENS];
    for (int i = 0; i < MAX_TOKENS; i++) {
        tokens[i] = NULL;
    }

    // Walk through other tokens
    for(int i = 0; token != NULL && i < MAX_TOKENS; i++) {
        tokens[i] = token;

        token = strtok(NULL, " ");
    }
    
    for(int i = 0; tokens[i] != NULL; i++) {
        printf("TOKENS: %s\n", tokens[i]);
    }

    printf("MAC address found: %s!\n", tokens[3]);

    return tokens[3];
}