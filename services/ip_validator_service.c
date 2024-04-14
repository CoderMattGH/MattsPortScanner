#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>

#include <netinet/in.h>

#include "ip_validator_service.h"
#include "network_helper.h"
#include "../constants/constants.h"

unsigned char validate_ip_str(const char* ip_str) {
    if (DEBUG >= 2) {
        printf("Validating IP address string...\n");
    }

    if (ip_str == NULL) {
        if (DEBUG >= 2) {
            printf("IP address string cannot be NULL!\n");
        }

        return 0;
    }

    char *str = malloc(sizeof(char) * 30);
    memset(str, 0, sizeof(char) * 30);
    strcpy(str, ip_str);

    const char *delim = ".";

    char *token = strtok(str, delim);

    if (token == NULL) {
        return 0;
    }

    int i = 0;
    for (i = 0; token != NULL; i++) {
        // If more than 3 digits then not valid
        if (i >= IP_LEN) {
            if (DEBUG >= 2) {
                printf("IP address is too long!\n");
            }

            return 0;
        }

        errno = 0;

        long int num = strtol(token, NULL, 10);

        // Check no error occurred
        if (errno != 0) {
            if (DEBUG >= 2) {
                printf("Could not parse integer from IP string token!\n");
            }

            return 0;
        }

        // First and last digit cannot be 0
        if ((i == 0 || i == 3) && (num == 0)) {
            if (DEBUG >= 2) {
                printf("First and last digit of IP address cannot be 0!\n");
            }

            return 0;
        } 
        
        if (num < 0 || num > 255) {
            if (DEBUG >= 2) {
                printf("IP address is outside of valid range!\n");
            }
            
            return 0;
        }

        token = strtok(NULL, delim);
    }

    // Check that IP address is 4 blocks of numbers
    if (i != 3) {
        if (DEBUG >= 2) {
            printf("IP address is not the correct length!\n");
        }

        return 0;
    }

    if (DEBUG >= 2) {
        printf("IP address is valid!\n");
    }

    return 1;
}

unsigned char validate_ip_arr(const unsigned char *ip_arr) {
    if (DEBUG >= 2) {
        printf("Validating IP address array...");
    }

    if (ip_arr == NULL) {
        if (DEBUG >= 2) {
            printf("IP address array cannot be NULL!\n");
        }

        return 0;
    }

    for (int i = 0; i < IP_LEN; i++) {
        if ((i == 0 || i == 3) && (ip_arr[i] == 0)) {
            if (DEBUG >= 2) {
                printf("First and last digit of IP address cannot be 0!\n");

                return 0;
            }
        }

        if (ip_arr[i] < 0 || ip_arr[i] > 255) {
            if (DEBUG >= 2) {
                printf("IP address it out of range!\n");
            }
        }
    }

    if (DEBUG >= 2) {
        printf("IP address is valid!\n");
    }

    return 1;
}

unsigned char validate_ip_add(struct in_addr* ip_add) {
    if (DEBUG >= 2) {
        printf("Validating IP address...\n");
    }

    if (ip_add == NULL) {
        if (DEBUG >= 2) {
            printf("IP address cannot be NULL!\n");

            return 0;
        }
    }

    unsigned char *temp_ip = get_ip_arr_rep(ip_add);

    return validate_ip_arr(temp_ip);
}