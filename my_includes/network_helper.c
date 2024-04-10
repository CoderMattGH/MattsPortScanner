#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network_helper.h"
#include "process_service.h"
#include "constants.h"

int get_interface_index(const int *sock, const char *dev_name) {
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
    
    snprintf(str, BUFF_SIZE - 1, "%02x:%02x:%02x:%02x:%02x:%02x", mac_add[0], 
            mac_add[1], mac_add[2], mac_add[3], mac_add[4], mac_add[5]);
    
    return str;
}

char * get_ip_str(const struct in_addr *ip_add) {
    const int STR_SIZE = INET_ADDRSTRLEN * sizeof(char);
    char *ip_str = malloc(STR_SIZE);
    memset(ip_str, 0, STR_SIZE);

    if (inet_ntop(AF_INET, ip_add, ip_str, INET_ADDRSTRLEN) == NULL) {
        return NULL;
    }

    return ip_str;
}

char * get_ip_arr_str(const unsigned char *ip_add) {
    const int STR_SIZE = INET_ADDRSTRLEN * sizeof(char);
    char *ip_str = malloc(STR_SIZE);
    memset(ip_str, 0, STR_SIZE);

    sprintf(ip_str, "%d.%d.%d.%d", ip_add[0], ip_add[1], ip_add[2], ip_add[3]);

    return ip_str;
}

struct in_addr * get_ip_from_str(const char *ip_str){
    struct in_addr *ip_add = malloc(sizeof(struct in_addr));
    memset(ip_add, 0, sizeof(struct in_addr));

    if (inet_pton(AF_INET, ip_str, ip_add) < 1) {
        return NULL;
    }

    return ip_add;
}

unsigned char * get_mac_from_str(const char *mac_str) {
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

unsigned char * get_mac_address(const int *sock, const char *dev_name) {
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

struct in_addr * get_ip_address(const int *sock, const char *dev_name) {
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

struct ifreq * get_ifreq_struct(const char *dev_name) {
    struct ifreq *structure = malloc(sizeof(struct ifreq));
    memset(structure, 0, sizeof(struct ifreq));
    strncpy(structure->ifr_name, dev_name, IFNAMSIZ - 1);

    return structure;
}

unsigned char * get_ip_arr_rep(const struct in_addr *ip_add) {
    union ip_address {
        struct in_addr def_rep;
        unsigned char arr_rep[4];
    };

    union ip_address un;
    un.def_rep = *ip_add;

    unsigned char *ip_arr = malloc(sizeof(char) * IP_LEN);
    memset(ip_arr, 0, sizeof(char) * IP_LEN);

    for (int i = 0; i < IP_LEN; i++) {
        ip_arr[i] = un.arr_rep[i];
    }

    return ip_arr;
}

struct in_addr * get_gw_ip_address(const char *dev_name) {
    if (DEBUG >= 2) {
        printf("Trying to find IP address of default gateway\n");
    }

    const char* path = "route -n | grep ";

    const int MAX_PATH_BUFF = 200;
    char* path_buff = malloc(sizeof(char) * MAX_PATH_BUFF);
    memset(path_buff, 0, sizeof(MAX_PATH_BUFF * sizeof(char)));
    
    strncpy(path_buff, path, 100);
    strncat(path_buff, dev_name, 99);

    char **output = load_process(path_buff);

    free(path_buff);

    if (output == NULL) {
        return NULL;
    }

    char *token;
    for (int i = 0; output[i] != NULL; i++) {
        // Tokenise output to help parse
        token = strtok(output[i], " ");

        for (int j = 0; token != NULL; j++) {
            if(strcmp("0.0.0.0", token) == 0) {
                if (DEBUG >= 2) {
                    printf("Default gateway row identified\n");
                }

                // Next token should be default gateway IP address
                token = strtok(NULL, " ");
                
                // IP address not found
                if (token == NULL) {
                    return NULL;
                }
                
                struct in_addr *ip_add = get_ip_from_str(token);

                if (ip_add == NULL)
                    return NULL;

                if (DEBUG >= 2) {
                    printf("Default gateway IP found: %s!\n", 
                            get_ip_str(ip_add));
                }

                free(output);

                return ip_add;
            }     
            
            token = strtok(NULL, " ");
        }
    }

    free(output);

    return NULL;
}

unsigned char * get_ip_32_arr(unsigned int ip_add) {
    unsigned char *ip_arr = malloc(sizeof(char) * IP_LEN);
    memset(ip_arr, 0, sizeof(char) * IP_LEN);

    for (int i = 0; i < IP_LEN; i++) {
        ip_arr[i] = ((unsigned char *)&(ip_add))[i];
    }

    return ip_arr;
}

char * get_ip_32_str(unsigned int ip_add) {
    char *ip_str = get_ip_arr_str(get_ip_32_arr(ip_add));

    return ip_str;
}

char * compare_ip_add(const unsigned char *ip_add_a, 
        const unsigned char *ip_add_b) {
    int equal = 0;
    for (int i = 0; i < IP_LEN; i++) {
        if (ip_add_a[i] != ip_add_b[i]) {
            equal = -1;
            break;
        }
    }

    return equal;
}

char * compare_mac_add(const unsigned char *mac_add_a,
        const unsigned char *mac_add_b) {
    int equal = 0;
    for (int i = 0; i < MAC_LEN; i++) {
        if (mac_add_a[i] != mac_add_b[i]) {
            equal = -1;
            break;
        }
    }

    return equal;
}