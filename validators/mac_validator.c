#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mac_validator.h"
#include "../constants/constants.h"

unsigned char validate_mac_add(const unsigned char *mac_add) {
    if (DEBUG >= 2) {
        printf("Validating MAC address...\n");
    }

    if (mac_add == NULL) {
        if (DEBUG >= 2) {
            printf("MAC address cannot be NULL!\n");
        }

        return 0;
    }

    for (int i = 0; i < MAC_LEN; i++) {
        if (mac_add[i] < 0 || mac_add[i] > 255) {
            if (DEBUG >= 2) {
                printf("MAC address is outside of valid range\n");
            }

            return 0;
        }
    }

    if (DEBUG >= 2) {
        printf("MAC address is valid!\n");
    }
}

