#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <math.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "scanning_service.h"
#include "network_helper.h"
#include "packet_service.h"
#include "tcp_service.h"
#include "../constants/constants.h"

int * scan_ports_raw_multi(const unsigned char *src_ip,
        const unsigned char *tar_ip, const unsigned char *src_mac,
        const unsigned char *tar_mac, int start_port, int end_port, 
        int inter_index) {
    if (start_port < 1 || end_port > MAX_PORT) {
        fprintf(stderr, "ERROR: Ports must be between 0 and %d\n", MAX_PORT);
        
        return NULL;
    }

    if (DEBUG >= 0) {
        printf("Commencing multithreaded scan of target: %s\n", 
                get_ip_arr_str(tar_ip));
    }

    pthread_t tid;
    
    struct scan_raw_port_args *args = malloc(sizeof(struct scan_raw_port_args));
    memset(args, 0, sizeof(struct scan_raw_port_args));

    unsigned char finished = 0;

    args->src_ip = src_ip;
    args->tar_ip = tar_ip;
    args->src_mac = src_mac;
    args->tar_mac = tar_mac;
    args->inter_index = inter_index;

    args->start_port = start_port;
    args->end_port = end_port;
    args->finished = &finished;

    if (args->end_port > MAX_PORT)
        args->end_port = MAX_PORT;

    pthread_create(&tid, NULL, scan_ports_raw_proxy, (void *)args);

    listen_for_ACK_replies(tar_ip, src_mac, &finished);
}

int * scan_ports_raw_arr_multi(const unsigned char *src_ip, 
        const unsigned char *tar_ip, const unsigned char *src_mac,
        const unsigned char *tar_mac, const unsigned short *ports, 
        int ports_len, int inter_index) {
    if (DEBUG >= 0) {
        printf("Commencing scan of target: %s\n", get_ip_arr_str(tar_ip));
    }

    pthread_t tid;

    // Value shared between threads to indicate when the port scan has finished
    unsigned char finished = 0;

    struct scan_raw_arr_args *args = malloc(sizeof(struct scan_raw_arr_args));
    memset(args, 0, sizeof(struct scan_raw_arr_args));

    args->src_ip = src_ip;
    args->tar_ip = tar_ip;
    args->src_mac = src_mac;
    args->tar_mac = tar_mac;
    args->inter_index = inter_index;

    args->ports = ports;
    args->ports_len = ports_len;

    args->finished = &finished;

    pthread_create(&tid, NULL, scan_ports_raw_arr_proxy, (void *) args);

    listen_for_ACK_replies(tar_ip, src_mac, &finished);
}

void * scan_ports_raw_arr_proxy(void *scan_args) {
    struct scan_raw_arr_args *args = (struct scan_raw_arr_args *)scan_args;

    if (DEBUG >= 3) {
        printf("SYN packet sending thread created\n");
    }

    scan_ports_raw_arr(args->src_ip, args->tar_ip, args->src_mac, args->tar_mac, 
            args->ports, args->ports_len, args->inter_index);

    printf("Finished scan!\n");

    // Sleep for 5 seconds and then signal all packets were sent
    sleep(SLEEP_S_AFTER_FINISH);
    *(args->finished) = 1;

    // Garbage collection
    free(scan_args);
}

void * scan_ports_raw_proxy(void *scan_args) {
    struct scan_raw_port_args *args = (struct scan_raw_port_args *)scan_args;

    if (DEBUG >= 3) {
        printf("SYN packet sending thread created\n");
    }

    scan_ports_raw(args->src_ip, args->tar_ip, args->src_mac, args->tar_mac,
            args->start_port, args->end_port, args->inter_index);

    sleep(SLEEP_S_AFTER_FINISH);
    *(args->finished) = 1;

    // Garbage collection
    free(scan_args);
}

int scan_ports_raw(const unsigned char *src_ip, const unsigned char *tar_ip, 
        const unsigned char *src_mac, const unsigned char *tar_mac,
        int start_port, int end_port, int inter_index) {
    if (start_port < 1 || end_port > MAX_PORT) {
        fprintf(stderr, "ERROR: Ports must be between 0 and %d\n", MAX_PORT);
        
        return -1;
    }

    if (DEBUG >= 3) {
        printf("Scanning host: %s: %d - %d\n", get_ip_arr_str(src_ip), 
                start_port, end_port);
    }

    int sock_raw;

    // Sleep time inbetween sending packets in microseconds
    //const int SLEEP_TIME_MICS = 1000 * 1000 * 0.000000001;
    const int SLEEP_TIME_MICS = 0;

    for (int curr_port = start_port; curr_port <= end_port; curr_port++) {
        // Randomise source port
        int src_port = get_random_port_num();

        // Raw socket
        sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

        if (sock_raw < 0) {
            return -1;
        }

        // Construct the TCP SYN packet
        unsigned char* packet = construct_syn_packet(get_ip_arr_str(src_ip), 
                get_ip_arr_str(tar_ip), src_mac, tar_mac, src_port, curr_port);
        
        int send_len = send_packet(packet, 64, sock_raw, inter_index, src_mac);

        free(packet);
        close(sock_raw);

        if (send_len < 0) {
            fprintf(stderr, "ERROR: Problem sending SYN packet!");
            
            return -1;
        }

        if (DEBUG >= 3) {
            printf("Successfully sent SYN packet to %s:%d\n", 
                    get_ip_arr_str(tar_ip), curr_port);
        }

        usleep(SLEEP_TIME_MICS);
    }

    return 0;
}

int scan_ports_raw_arr(const unsigned char *src_ip, 
        const unsigned char *tar_ip, const unsigned char *src_mac,
        const unsigned char *tar_mac, const unsigned short *ports, 
        int ports_len, int inter_index) {
    if (DEBUG >= 3)
        printf("Scanning host: %s: \n", get_ip_arr_str(src_ip));

    int sock_raw;

    // Sleep time inbetween sending packets in microseconds
    const int SLEEP_TIME_MICS = 1000 * 1000 * 0.1;

    for (int i = 0; i < ports_len; i++) {
        int src_port = get_random_port_num();
        int curr_port = ports[i];

        // Raw socket
        sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

        if (sock_raw < 0) {
            return -1;
        }

        // Construct the TCP SYN packet
        unsigned char* packet = construct_syn_packet(get_ip_arr_str(src_ip),
                get_ip_arr_str(tar_ip), src_mac, tar_mac, src_port, curr_port);
        
        int send_len = send_packet(packet, 64, sock_raw, inter_index, src_mac);

        close(sock_raw);
        free(packet);

        if (send_len < 0) {
            fprintf(stderr, "ERROR: Problem sending SYN packet!");

            return -1;
        }

        if (DEBUG >= 3) {
            printf("Successfully sent SYN packet to %s:%d\n", 
                    get_ip_arr_str(tar_ip), curr_port);
        }

        usleep(SLEEP_TIME_MICS);
    }

    return 0;
}

unsigned short int get_random_port_num() {
    static unsigned char seeded = 0;

    if (seeded == 0) {
        srand(0);
        seeded = 1;
    }

    const int START = 100;
    const int END = MAX_PORT;

    return (unsigned short int)((rand() % (START - END + 1)) + START);
}