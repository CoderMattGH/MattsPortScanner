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

#include <net/if_arp.h>

#include "my_includes/network_helper.h"
#include "my_includes/packet_service.h"
#include "my_includes/arp_service.h"
#include "my_includes/process_service.h"
#include "my_includes/icmp_service.h"
#include "my_includes/constants.h"

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

    // Search the ARP table for the MAC address associated with dest_ip.
    mac_dest = get_mac_add_from_ip(get_ip_arr_rep(dest_ip), sock_raw,
            loc_mac_add, get_ip_arr_rep(loc_ip_add), loc_int_index, dev_name);

    if (mac_dest == NULL) {
        fprintf(stderr, "ERROR: Cannot get MAC address of destination IP!\n");

        return -1;
    }

    // Verbose tag
    printf("\n");
    printf("Information\n");
    printf("-----------\n\n");
    printf("Destination IP:             %s\n", get_ip_str(dest_ip));
    printf("Destination ports:          %d-%d\n", start_prt, end_prt);
    printf("Destination MAC address:    %s\n", get_mac_str(mac_dest));
    printf("Local network device:       %s\n", dev_name);

    printf("Local device index:         %d\n", loc_int_index);
    printf("Local MAC address:          %s\n", get_mac_str(loc_mac_add));
    printf("Local IP address:           %s\n\n", get_ip_str(loc_ip_add));

    // Send ICMP packet
    int icmp_ret_val = send_icmp_request(get_ip_str(loc_ip_add), 
            get_ip_str(dest_ip), loc_mac_add, mac_dest, sock_raw, 
            loc_int_index);
    
    if (icmp_ret_val < 0) {
        fprintf(stderr, "ERROR: Could not send ICMP packet!\n");

        return -1;
    }

    close(sock_raw);

    if (DEBUG >= 2) {
        printf("Exiting!\n");
    }

    return 0;
}