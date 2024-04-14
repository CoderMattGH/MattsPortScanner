#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "checksum_service.h"
#include "constants.h"

unsigned short ip_checksum(const unsigned short* start_of_header) {
    if (DEBUG >= 3) {
        printf("\n");
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

    if (DEBUG >= 3) {
        printf("IP header checksum:     0x%x\n\n", result);
    }

    return result;
}

unsigned short tcp_checksum(const unsigned short* start_of_header, 
        const unsigned short *start_of_pseudo_header) {
    if (DEBUG >= 3) {
        printf("Calculating TCP header checksum\n");
    }

    if (DEBUG >= 3) {
        printf("\n");
        printf("TCP Checksum\n");
        printf("------------\n\n");
        printf("source:                 %d\n", start_of_header[0]);
        printf("dest:                   %d\n", start_of_header[1]);
        printf("seq(1):                 %d\n", start_of_header[2]);
        printf("seq(2):                 %d\n", start_of_header[3]);
        printf("ack_seq(1):             %d\n", start_of_header[4]);
        printf("ack_seq(2):             %d\n", start_of_header[5]);
        printf("doff,reserved,flags:    %d\n", start_of_header[6]);
        printf("window:                 %d\n", start_of_header[7]);
        printf("checksum:               %d\n", start_of_header[8]);
        printf("urg_ptr:                %d\n", start_of_header[9]);
        printf("data:                   0\n\n");    // No data payload
    }

    if (DEBUG >= 3) {
        printf("Pseudo Header\n");
        printf("-------------\n\n");
        printf("saddr(1):               %d\n", start_of_pseudo_header[0]);
        printf("saddr(2):               %d\n", start_of_pseudo_header[1]);
        printf("daddr(1):               %d\n", start_of_pseudo_header[2]);
        printf("daddr(2):               %d\n", start_of_pseudo_header[3]);
        printf("reserved + protocol:    %d\n", start_of_pseudo_header[4]);
        printf("tcpseglen:              %d\n\n", start_of_pseudo_header[5]);
    }

    unsigned long sum = 0;

    // Calculate Pseudo header checksum
    for (int i = 0; i < 7; i++) {
        sum += start_of_pseudo_header[i];

        // Detect carry
        if (sum > 65545) {
            sum = sum & 0x0000FFFF;
            sum += 1;
        }
    }

    // Calculate TCP header checksum
    for (int i = 0; i < 12; i++) {
        sum += start_of_header[i];

        // Detect carry
        if (sum > 65545) {
            sum = sum & 0X0000FFFF;
            sum += 1;
        }
    }

    unsigned short result = ~((unsigned short)(sum & 0X0000FFFF));

    if (DEBUG >= 3) {
        printf("Total TCP Checksum:     0x%x\n\n", result);
    }

    return result;
}

unsigned short icmp_checksum(const unsigned short* start_of_header) {
    const int NUM_16_WORDS = 4;
    
    if (DEBUG >= 2) {
        printf("\n");
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
        printf("ICMP header checksum:   0x%x\n\n", result);
    }

    return result;
}