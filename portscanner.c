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
#include <errno.h>
#include <net/if_arp.h>

#include "my_includes/network_helper.h"
#include "my_includes/packet_service.h"
#include "my_includes/arp_service.h"
#include "my_includes/process_service.h"
#include "my_includes/icmp_service.h"
#include "my_includes/scanning_service.h"
#include "my_includes/tcp_service.h"
#include "my_includes/constants.h"

const unsigned short int COMM_POR_TCP[] = {
    20,         // FTP
    21,         // FTP
    22,         // SSH
    23,         // TELNET
    25,         // SMTP
    42,         // WINS
    43,         // WHOIS
    49,         // TACACS
    53,         // DNS
    69,         // TFTP
    70,         // GOPHER
    79,         // FINGER
    80,         // HTTP
    88,         // KERBEROS
    102,        // TSAP
    110,        // POP3
    113,        // IDENT
    119,        // NNTP (Usenet)
    123,        // NTP
    135,        // Ms RPC EPMAP
    137,        // NETBIOS NS
    138,        // NETBIOS (Datagram service)
    139,        // NETBIOS (Session service)
    143,        // IMAP
    161,        // SNMP
    179,        // Border Gateway Protocol
    194,        // IRC
    201,        // AppleTalk
    264,        // Border Gateway Multicast Protocol
    389,        // LDAP
    443,        // HTTPS
    445,        // SMB
    554,        // RTSP
    993,        // IMAPS
    995,        // POP3S
    1025,       // MS RPC
    1080,       // SOCKS
    1720,       // H.323
    2082,       // CPANEL
    3128,       // HTTP PROXY
    3306,       // MYSQL
    3389,       // RDP
    5060,       // SIP
    5061,       // SIP over TLS
    5432,       // POSTGRESQL
    6379,       // REDIS
    6970,       // QUICKTIME STREAMING SERVER
    8000,       // INTERNET RADIO
    8080,       // HTTP PROXY
    8200,       // VMWARE SERVER
    8222,       // VMWARE SERVER
    9092,       // KAFKA
    19226,      // ADMINSECURE
    27017       // MONGODB
};

const int COMM_POR_TCP_SZ 
        = sizeof(COMM_POR_TCP) / sizeof(unsigned short int);

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("usage: mps <destination_ip> <interface_name>\n");

        return 0;
    }

    printf("===================\n");
    printf("Matt's Port Scanner\n");
    printf("===================\n\n");

    // Boolean specifying whether to perform a full port scan
    unsigned char full_scan = 0;

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
        close(sock_raw);

        return -1;
    }

    // Get MAC address of the interface
    loc_mac_add = get_mac_address(&sock_raw, dev_name);
    if (loc_mac_add == NULL) {
        fprintf(stderr, "ERROR: Cannot get MAC address.\n");
        close(sock_raw);

        return -1;
    }

    // Get IP address of the interface
    loc_ip_add = get_ip_address(&sock_raw, dev_name);
    if (loc_ip_add == NULL) {
        fprintf(stderr, "ERROR: Cannot get IP address.\n");
        close(sock_raw);

        return -1;
    }

    // Initialise random number seed
    srand(0);

    // Search the ARP table for the MAC address associated with dest_ip.
    mac_dest = get_mac_add_from_ip(get_ip_arr_rep(dest_ip), sock_raw,
            loc_mac_add, get_ip_arr_rep(loc_ip_add), loc_int_index, dev_name);

    if (mac_dest == NULL) {
        fprintf(stderr, "ERROR: Cannot get MAC address of destination IP!\n");
        close(sock_raw);

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

    // Ping target
    int ping_ret_val = ping_target(get_ip_arr_rep(loc_ip_add), 
            get_ip_arr_rep(dest_ip), loc_mac_add, mac_dest, sock_raw, 
            loc_int_index);

    switch(ping_ret_val) {
        // ICMP reply received
        case(1):
            if (DEBUG >= 2) {
                printf("Target IP (%s) is up.\n", get_ip_str(dest_ip));
            }
            
            close(sock_raw);

            // Commence port scan
            if (full_scan == 1) {
                scan_ports_raw_multi(get_ip_arr_rep(loc_ip_add), 
                        get_ip_arr_rep(dest_ip), loc_mac_add, mac_dest, 1, 
                        MAX_PORT, loc_int_index);
            } else {
                scan_ports_raw_arr_multi(get_ip_arr_rep(loc_ip_add),
                        get_ip_arr_rep(dest_ip), loc_mac_add, mac_dest, 
                        COMM_POR_TCP, COMM_POR_TCP_SZ, loc_int_index);
            }

            break;
        // ICMP reply not received
        case(0):
            if (DEBUG >= 2) {
                printf("Target IP (%s) is down or not responding to ping " 
                        "requests\n", get_ip_str(dest_ip));
            }

            break;
        // An error occurred
        case(-1):
        default:
            fprintf(stderr, 
                    "ERROR: An unknown error occurred with the ICMP request\n");
            close(sock_raw);

            return -1;
    }

    if (DEBUG >= 2) {
        printf("Exiting!\n");
    }

    close(sock_raw);

    return 0;
}