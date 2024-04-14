#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "packet_service.h"
#include "network_helper.h"
#include "constants.h"

int send_packet(const unsigned char *packet, int packet_len, int socket, 
        int dev_index, const unsigned char *mac_src) {
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

    if (DEBUG >= 3) {
        printf("Packet successfully sent with length: %d bytes\n", send_len);
    }

    return send_len;
}