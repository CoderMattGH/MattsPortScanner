#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "validate_port.h"
#include "../constants/constants.h"

int validate_port(unsigned short port) {
    if (DEBUG >= 2) {
        printf("Validating port...\n");
    }

    if (port < 1 || port > MAX_PORT) {
        if (DEBUG >= 2) {
            printf("Port is invalid!");
        }

        return 0;
    }

    if (DEBUG >= 2) {
        printf("Port is valid\n");
    }

    return 1;
}

int validate_port_range(unsigned short start_port, unsigned short end_port) {
    if (DEBUG >= 2) {
        printf("Validating port range...\n");
    }

    if ((validate_port(start_port) == 0) || (validate_port(end_port) == 0)) {
        if (DEBUG >= 2) {
            printf("Ports are invalid!\n");
        }

        return 0;
    }

    if (start_port > end_port) {
        if (DEBUG >= 2) {
            printf("start_port cannot be larger than end_port\n");
        }

        return 0;
    }

    if (DEBUG >= 2) {
        printf("Port range is valid!\n");
    }

    return 1;
}