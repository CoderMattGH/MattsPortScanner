#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>

#include "validator_service.h"
#include "../constants/constants.h"

unsigned char validate_ip_str(const char* ip_str) {
    if (DEBUG >= 2) {
        printf("Validating IP address...\n");
    }

    if (ip_str == NULL) {
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

        // Check if first digit is between 1 and 255
        long int num = strtol(token, NULL, 10);

        // Check no error occurred
        if (errno != 0) {
            if (DEBUG >= 2) {
                printf("Could not parse integer from IP string token!\n");
            }

            return 0;
        }

        // First and last digit cannot be 0
        if (i == 0 || i == 3) {
            if (num <= 0 || num >= 255) {
                if (DEBUG >= 2) {
                    printf("IP address is outside of valid range!\n");
                }

                return 0;
            }
        } 
        else if (num < 0 || num > 255) {
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