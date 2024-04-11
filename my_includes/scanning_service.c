#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include <math.h>

#include <pthread.h>

#include "scanning_service.h"
#include "network_helper.h"
#include "packet_service.h"
#include "constants.h"

struct scan_port_args {
    struct in_addr *tar_ip;
    int start_port;
    int end_port;
};

struct scan_raw_port_args {
    const unsigned char *src_ip;
    const unsigned char *tar_ip;
    const unsigned char *src_mac;
    const unsigned char *tar_mac;
    int start_port;
    int end_port;
    int inter_index;
};

int * scan_ports_multi(struct in_addr *tar_ip, int start_port, int end_port) {
    if (start_port < 1 || end_port > MAX_PORT) {
        fprintf(stderr, "ERROR: Ports must be between 0 and %d\n", MAX_PORT);
        
        return NULL;
    }

    if (DEBUG >= 2) {
        printf("Commencing multithreaded scan of target: %s\n", 
                get_ip_str(tar_ip));
    }

    pthread_t tid[MAX_THREADS];
    
    // Number of ports each thread should scan
    int port_chunk = (int)(ceil((end_port - start_port) / (double)MAX_THREADS));
    
    if (DEBUG >= 2) {
        printf("Creating %d threads to scan in chunks of %d ports\n", 
                MAX_THREADS, port_chunk);
    }
    for (int i = 0; i < MAX_THREADS; i++) {
        struct scan_port_args *args = malloc(sizeof(struct scan_port_args));
        memset(args, 0, sizeof(struct scan_port_args));

        args->tar_ip = tar_ip;

        args->start_port = start_port + (port_chunk * i);
        args->end_port = args->start_port + port_chunk - 1;

        if (args->end_port > MAX_PORT) {
            args->end_port = MAX_PORT;
        }

        pthread_create(&tid[i], NULL, scan_ports_proxy, (void *)args);        
    }

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(tid[i], NULL);
    }

    return NULL;
}

int * scan_ports_raw_multi(const unsigned char *src_ip,
        const unsigned char *tar_ip, const unsigned char *src_mac,
        const unsigned char *tar_mac, int start_port, int end_port, 
        int inter_index) {
    if (start_port < 1 || end_port > MAX_PORT) {
        fprintf(stderr, "ERROR: Ports must be between 0 and %d\n", MAX_PORT);
        
        return NULL;
    }

    if (DEBUG >= 2) {
        printf("Commencing multithreaded scan of target: %s\n", 
                get_ip_arr_str(tar_ip));
    }

    pthread_t tid[MAX_THREADS];
    
    // Number of ports each thread should scan
    int port_chunk = (int)(ceil((end_port - start_port) / (double)MAX_THREADS));
    
    if (DEBUG >= 2) {
        printf("Creating %d threads to scan in chunks of %d ports\n", 
                MAX_THREADS, port_chunk);
    }
    for (int i = 0; i < MAX_THREADS; i++) {
        struct scan_raw_port_args *args = 
                malloc(sizeof(struct scan_raw_port_args));
        memset(args, 0, sizeof(struct scan_raw_port_args));

        args->src_ip = src_ip;
        args->tar_ip = tar_ip;
        args->src_mac = src_mac;
        args->tar_mac = tar_mac;
        args->inter_index = inter_index;

        args->start_port = start_port + (port_chunk * i);
        args->end_port = args->start_port + port_chunk - 1;

        if (args->end_port > MAX_PORT) {
            args->end_port = MAX_PORT;
        }

        pthread_create(&tid[i], NULL, scan_ports_raw_proxy, (void *)args);
    }

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(tid[i], NULL);
    }
}

void * scan_ports_proxy(void *scan_args) {
    struct scan_port_args *args = (struct scan_port_args *)scan_args;

    if (DEBUG >= 3) {
        printf("Creating thread\n");
    }

    scan_ports(args->tar_ip, args->start_port, args->end_port);

    // Garbage collection
    free(scan_args);
}

void * scan_ports_raw_proxy(void *scan_args) {
    struct scan_raw_port_args *args = (struct scan_raw_port_args *)scan_args;

    if (DEBUG >= 3) {
        printf("Creating thread\n");
    }

    scan_ports_raw(args->src_ip, args->tar_ip, args->src_mac, args->tar_mac,
            args->start_port, args->end_port, args->inter_index);

    // Garbage collection
    free(scan_args);
}

int * scan_ports(struct in_addr *tar_ip, int start_port, int end_port) {
    if (start_port < 1 || end_port > MAX_PORT) {
        fprintf(stderr, "ERROR: Ports must be between 0 and %d\n", MAX_PORT);
        
        return NULL;
    }

    if (DEBUG >= 3) {
        printf("Scanning host: %s: %d - %d\n", get_ip_str(tar_ip), start_port,
                end_port);
    }

    struct sockaddr_in serv_addr;
    struct hostent* server;
    int sockfd;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr = *tar_ip;

    // Initialise to all zeros.
    int open_ports[MAX_PORT + 1] = {0};

    for (int curr_port = start_port; curr_port <= end_port; curr_port++) {
        // Non-blocking socket
        sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

        if (sockfd < 0) {
            return NULL;
        }

        // Change the port number
        serv_addr.sin_port = htons(curr_port);

        // Timeout in seconds
        const int TIMEOUT_SECS = 7;

        // Sleep time in milliseconds
        const int SLEEP_TIME_MILS = 1000 * 1000 * 0.001;

        long int start_time = time(0);
        long int curr_time = time(0);

        // Spin on non-blocking connect
        while ((curr_time - start_time) <= TIMEOUT_SECS) {
            // Get current time
            curr_time = time(0);

            // Reset errno
            errno = 0;

            // Try to connect
            int conn_val = connect(sockfd, (struct sockaddr *)&serv_addr, 
                    sizeof(serv_addr));
            
            if (conn_val < 0) {
                if (errno == EAGAIN || errno == EALREADY 
                        || errno == EINPROGRESS) {

                    // sleep for 0.1 seconds
                    usleep(SLEEP_TIME_MILS);

                    continue;
                }
                else {
                    close(sockfd);

                    break;
                }
            } 

            if (DEBUG >= 2) {
                printf("Open port detected: %d\n", curr_port);
            }

            open_ports[curr_port] = 1;
        }

        close(sockfd);

        usleep(1);
    }

    return NULL;
}

int * scan_ports_raw(const unsigned char *src_ip, const unsigned char *tar_ip, 
        const unsigned char *src_mac, const unsigned char *tar_mac,
        int start_port, int end_port, int inter_index) {
    if (start_port < 1 || end_port > MAX_PORT) {
        fprintf(stderr, "ERROR: Ports must be between 0 and %d\n", MAX_PORT);
        
        return NULL;
    }

    if (DEBUG >= 3) {
        printf("Scanning host: %s: %d - %d\n", get_ip_arr_str(src_ip), 
                start_port, end_port);
    }

    int sock_raw;

    // Initialise to all zeros.
    int open_ports[MAX_PORT + 1] = {0};

    for (int curr_port = start_port; curr_port <= end_port; curr_port++) {
        // WAY TO CHECK THAT PORT IS NOT IN USE?
        int src_port = 8000;

        // Non-blocking socket
        sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

        if (sock_raw < 0) {
            return NULL;
        }

        // Construct the TCP SYN packet
        unsigned char* packet = construct_syn_packet(get_ip_arr_str(src_ip), 
                get_ip_arr_str(tar_ip), src_mac, tar_mac, src_port, curr_port);

        // Send packet
        struct sockaddr_ll sadr_ll;
        sadr_ll.sll_ifindex = inter_index;
        sadr_ll.sll_halen = ETH_ALEN;
        
        for (int i = 0; i < MAC_LEN; i++) {
            sadr_ll.sll_addr[i] = tar_mac[i];
        }

        int send_len = sendto(sock_raw, packet, 64, 0, 
                (const struct sockaddr *)&sadr_ll, sizeof(struct sockaddr_ll));

        if (send_len < 0) {
            fprintf(stderr, "ERROR: Problem sending SYN packet!");
            
            return NULL;
        }

        if (DEBUG >= 2) {
            printf("Successfully sent SYN packet to %s:%d\n", 
                    get_ip_arr_str(tar_ip), curr_port);
        }

        close(sock_raw);
        
        // Timeout in seconds
        const int TIMEOUT_SECS = 7;

        // Sleep time in milliseconds
        const int SLEEP_TIME_MILS = 1000 * 1000 * 0.001;

        long int start_time = time(0);
        long int curr_time = time(0);

        /*
        // Spin on non-blocking connect
        while ((curr_time - start_time) <= TIMEOUT_SECS) {
            // Get current time
            curr_time = time(0);

            // Reset errno
            errno = 0;

            // Try to connect
            int conn_val = connect(sock_raw, (struct sockaddr *)&serv_addr, 
                    sizeof(serv_addr));
            
            if (conn_val < 0) {
                if (errno == EAGAIN || errno == EALREADY 
                        || errno == EINPROGRESS) {

                    // sleep for 0.1 seconds
                    usleep(SLEEP_TIME_MILS);

                    continue;
                }
                else {

                    break;
                }
            } 

            if (DEBUG >= 2) {
                printf("Open port detected: %d\n", curr_port);
            }

            open_ports[curr_port] = 1;
        }
        */

        usleep(1);
    }

    return NULL;
}

unsigned char * construct_syn_packet(const char *src_ip, const char *dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac, 
        unsigned short int src_port, unsigned short int dst_port) {
    if (DEBUG >= 2) {
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
    iph->protocol = 6;                  // ICMP

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