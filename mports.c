#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "mports.h"
#include "services/network_helper.h"
#include "services/arp_service.h"
#include "services/icmp_service.h"
#include "services/scanning_service.h"
#include "validators/ip_validator.h"
#include "constants/constants.h"

#include "validators/ip_validator.h"
#include "validators/mac_validator.h"
#include "validators/validate_port.h"

int main(int argc, const char *argv[]) {
    struct input_args *args = parse_input_args(argc, argv);

    if (args == NULL) {
        print_usage();

        return 0;
    }

    printf("Matt's Port Scanner v%s\n\n", VERSION);

    const unsigned char full_scan = !(args->simp_scan);
    const struct in_addr *dest_ip = args->tar_ip;
    const unsigned short start_prt = args->start_port;
    const unsigned short end_prt = args->end_port;
    const char *dev_name = args->dev_name;
    
    const unsigned char *mac_dest;                // Destination MAC address
    int loc_int_index;                            // Local interface index
    const unsigned char *loc_mac_add;             // Local MAC address
    const struct in_addr *loc_ip_add;             // Local IP address

    free(args);

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

    // Search the ARP table for the MAC address associated with dest_ip.
    mac_dest = get_mac_add_from_ip(get_ip_arr_rep(dest_ip), sock_raw,
            loc_mac_add, get_ip_arr_rep(loc_ip_add), loc_int_index, dev_name);

    if (mac_dest == NULL) {
        fprintf(stderr, "ERROR: Cannot get MAC address of destination IP!\n");
        close(sock_raw);

        return -1;
    }

    printf("\n");
    printf("Information\n");
    printf("-----------\n\n");
    printf("Destination IP:             %s\n", get_ip_str(dest_ip));

    if (full_scan) {
        printf("Destination ports:          %d-%d\n", start_prt, end_prt);
    }

    printf("Destination MAC address:    %s\n", get_mac_str(mac_dest));
    printf("Local network device:       %s\n", dev_name);
    printf("Local device index:         %d\n", loc_int_index);
    printf("Local MAC address:          %s\n", get_mac_str(loc_mac_add));
    printf("Local IP address:           %s\n\n", get_ip_str(loc_ip_add));

    // Ping target
    int ping_ret_val = ping_target(get_ip_arr_rep(loc_ip_add), 
            get_ip_arr_rep(dest_ip), loc_mac_add, mac_dest, sock_raw, 
            loc_int_index);

    close(sock_raw);

    // ICMP reply received
    if(ping_ret_val) {
        if (DEBUG >= 2) {
            printf("Target IP (%s) is up.\n", get_ip_str(dest_ip));
        }
        
        // Commence port scan
        if (full_scan == 1) {
            scan_ports_raw_multi(get_ip_arr_rep(loc_ip_add), 
                    get_ip_arr_rep(dest_ip), loc_mac_add, mac_dest, 1, 
                    MAX_PORT, loc_int_index);
        } else {
            unsigned short int *comm_ports = malloc(
                sizeof(unsigned short int) * MAX_PORT);
            memset(comm_ports, 0, sizeof(unsigned short int) * MAX_PORT);

            int comm_ports_len = get_common_ports_arr(comm_ports);

            // Reallocate common ports array to save memory
            comm_ports = realloc(comm_ports, 
                sizeof(unsigned short int) * comm_ports_len);

            if (comm_ports == NULL) {
                fprintf(stderr, "ERROR: Unknown error allocating memory!\n");

                return -1;
            }

            scan_ports_raw_arr_multi(get_ip_arr_rep(loc_ip_add),
                    get_ip_arr_rep(dest_ip), loc_mac_add, mac_dest, 
                    comm_ports, comm_ports_len, loc_int_index);
        }
    }
    else if (ping_ret_val == 0) {
    // ICMP reply not received
        if (DEBUG >= 0) {
            printf("Target IP (%s) is down or not responding to ping " 
                    "requests\n", get_ip_str(dest_ip));
        }
    }
    // An error occurred
    else if (ping_ret_val == -1) {
        fprintf(stderr, 
                "ERROR: An unknown error occurred with the ICMP request\n");

        return -1;
    }

    if (DEBUG >= 2) {
        printf("Exiting!\n");
    }

    return 0;
}

struct input_args * parse_input_args(int argc, const char **argv) {
    if (argc < 2) {
        print_usage();

        return NULL;
    }

    struct input_args *in_args = malloc(sizeof(struct input_args));
    memset(in_args, 0, sizeof(struct input_args));

    // Set defaults
    in_args->tar_ip = NULL;
    in_args->dev_name = NULL;
    in_args->simp_scan = 1;
    in_args->start_port = 1;
    in_args->end_port = MAX_PORT;

    const int MAX_TOK_LEN = 30;

    const char* IP_PARAM = "-ip";
    const char* DEV_PARAM = "-dev";
    const char* FULL_SCAN_FLAG = "-f";

    unsigned char ip_param_set = 0;
    unsigned char dev_param_set = 0;
    unsigned char full_scan_flag_set = 0;

    // Loop through input parameters and identify parameters and flags
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], IP_PARAM, strlen(IP_PARAM)) == 0) {
            if (ip_param_set) {
                return NULL;
            }

            // TODO: Validate IP here
            if (argv[i + 1] == NULL) {
                return NULL;
            }

            // Validate IP address string
            if (!validate_ip_str(argv[i + 1])) {
                return NULL;
            }
                
            in_args->tar_ip = get_ip_from_str(argv[i + 1]);

            ip_param_set = 1;
            i++;
        }
        else if (strncmp(argv[i], DEV_PARAM, strlen(DEV_PARAM)) == 0) {
            if (dev_param_set) {
                return NULL;
            }

            // Validate dev name
            if (argv[i + 1] == NULL || strlen(argv[i + 1]) < 1) {
                return NULL;
            }

            in_args->dev_name = argv[i + 1];
            dev_param_set = 1;
            i++;
        } 
        else if (
                strncmp(argv[i], FULL_SCAN_FLAG, strlen(FULL_SCAN_FLAG)) == 0) {
            if(full_scan_flag_set) {
                return NULL;
            }

            in_args->simp_scan = 0;
        } 
        else {
            return NULL;
        }
    }

    unsigned char load_prog = 1;
    
    if (in_args->tar_ip == NULL)
        load_prog = 0;
    
    if (in_args->dev_name == NULL)
        load_prog = 0;

    if (load_prog == 0)
        return NULL;
    else
        return in_args;
}

void print_usage() {
    printf("Matt's Port Scanner v%s\n", VERSION);
    printf("usage: mports [MANDATORY_PARAMS] [OPTIONAL_PARAMS]\n");
    printf("MANDATORY PARAMS:\n");
    printf("  -ip       <target_ipv4_address>\n");
    printf("  -dev      <network_interface_name>\n");
    printf("OPTIONAL PARAMS:\n");
    printf("  -f        Scans every TCP port between 1 and %d\n", MAX_PORT);
    printf("EXAMPLE:\n");
    printf("mports -ip 192.168.12.1 -dev enp4s0\n");
}

int get_common_ports_arr(unsigned short int *arr_copy) {
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

    const int arr_len = sizeof(COMM_POR_TCP) / sizeof(unsigned short int);

    // Copy array to arr_copy

    for(int i = 0; i < arr_len; i++) {
        arr_copy[i] = COMM_POR_TCP[i];
    }

    return arr_len;
}