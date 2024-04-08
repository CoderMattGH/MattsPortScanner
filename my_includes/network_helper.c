#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network_helper.h"

#ifndef DEBUG
    #define DEBUG 0
#endif

#define MAX_PORT 65535
#define MAC_LEN 6
#define IP_LEN 4

int get_interface_index(int *sock, char *dev_name) {
    struct ifreq *ifreq_i = get_ifreq_struct(dev_name);

    // On error
    if (ioctl(*sock, SIOCGIFINDEX, ifreq_i) < 0) {
        return -1;
    }

    int index = ifreq_i->ifr_ifindex;
    free(ifreq_i);

    return index;
}

char * get_mac_str(const unsigned char* mac_add) {
    const int BUFF_SIZE = sizeof(char) * 20;

    char * str = malloc(BUFF_SIZE);
    memset(str, 0, BUFF_SIZE);
    
    snprintf(str, BUFF_SIZE - 1, "%02x-%02x-%02x-%02x-%02x-%02x", mac_add[0], 
            mac_add[1], mac_add[2], mac_add[3], mac_add[4], mac_add[5]);
    
    return str;
}

char * get_ip_str(struct in_addr *ip_add) {
    const int STR_SIZE = INET_ADDRSTRLEN * sizeof(char);
    char *ip_str = malloc(STR_SIZE);
    memset(ip_str, 0, STR_SIZE);

    if (inet_ntop(AF_INET, ip_add, ip_str, INET_ADDRSTRLEN) == NULL) {
        return NULL;
    }

    return ip_str;
}

struct in_addr * get_ip_from_str(char *ip_str){
    struct in_addr *ip_add = malloc(sizeof(struct in_addr));
    memset(ip_add, 0, sizeof(struct in_addr));

    if (inet_pton(AF_INET, ip_str, ip_add) < 1) {
        return NULL;
    }

    return ip_add;
}

unsigned char * get_mac_from_str(char *mac_str) {
    int *mac_add = malloc(sizeof(int) * MAC_LEN);
    memset(mac_add, 0, sizeof(int) * MAC_LEN);

    unsigned char *mac_add_con = malloc(sizeof(char) * MAC_LEN);
    memset(mac_add_con, 0, sizeof(char) * MAC_LEN);

    sscanf(mac_str, "%2x:%2x:%2x:%2x:%2x:%2x", &mac_add[0], &mac_add[1], 
            &mac_add[2], &mac_add[3], &mac_add[4], &mac_add[5]);

    for (int i = 0; i < MAC_LEN; i++) {
        mac_add_con[i] = (unsigned char)mac_add[i];
    }

    free(mac_add);

    return mac_add_con;
}

unsigned char * get_mac_address(int *sock, char *dev_name) {
    struct ifreq *ifreq_c = get_ifreq_struct(dev_name);

    // On error
    if (ioctl(*sock, SIOCGIFHWADDR, ifreq_c) < 0) {
        return NULL;
    }

    unsigned char *mac_add = malloc(sizeof(unsigned char) * MAC_LEN);
    for (int i = 0; i < MAC_LEN; i++) {
        mac_add[i] = (unsigned char)ifreq_c->ifr_hwaddr.sa_data[i];
    }

    free(ifreq_c);

    return mac_add;
}

struct in_addr * get_ip_address(int *sock, char *dev_name) {
    struct ifreq *ifreq_ip = get_ifreq_struct(dev_name);

    // On error
    if (ioctl(*sock, SIOCGIFADDR, ifreq_ip) < 0) {
        return NULL;
    }

    struct in_addr temp = 
            ((struct sockaddr_in *)&(ifreq_ip->ifr_addr))->sin_addr;

    struct in_addr *ip_add = malloc(sizeof(struct sockaddr_in));
    memset(ip_add, 0, sizeof(struct sockaddr_in));
    memcpy(ip_add, &temp, sizeof(struct sockaddr_in));

    return ip_add;
}

struct ifreq * get_ifreq_struct(char *dev_name) {
    struct ifreq *structure = malloc(sizeof(struct ifreq));
    memset(structure, 0, sizeof(struct ifreq));
    strncpy(structure->ifr_name, dev_name, IFNAMSIZ - 1);

    return structure;
}