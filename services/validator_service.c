#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "validator_service.h"
#include "../constants/constants.h"

unsigned char validate_ip_str(const unsigned char* ip_str) {
    const char *delim = ".";
    char *token = strtok(ip_str, delim);

    while(token != NULL) {
        printf("", token);
    }
}