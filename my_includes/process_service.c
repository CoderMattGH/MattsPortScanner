#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "process_service.h"
#include "constants.h"

char ** load_process(const char* path) {
    if (DEBUG >= 2) {
        printf("Parsing output of process path: %s\n", path);
    }

    FILE *fp = popen(path, "r");

    if (fp == NULL) {
        return NULL;
    }

    const int MAX_OUTPUT_SIZE = 200;
    char *output = malloc(sizeof(char) * (MAX_OUTPUT_SIZE + 1));
    memset(output, 0, sizeof(char) * (MAX_OUTPUT_SIZE + 1));

    const int MAX_ARR_SIZE = 40;
    const int MAX_LINE_LEN = 200;
    char **ret_arr = malloc(sizeof(char *) * MAX_ARR_SIZE);
    for (int i = 0; i < MAX_ARR_SIZE; i++) {
        ret_arr[i] = malloc(sizeof(char) * (MAX_LINE_LEN + 1));
        memset(ret_arr[i], 0, sizeof(char) * (MAX_LINE_LEN + 1));
    }

    char* ret_val;
    int count = 0;
    
    while ((ret_val = fgets(output, MAX_OUTPUT_SIZE, fp)) != NULL) {
        if (count >= (MAX_ARR_SIZE - 1)) {
            break;
        }

        // Remove new line from output
        output[strcspn(output, "\n")] = 0;

        // Copy output string to array
        strncpy((ret_arr[count++]), output, MAX_LINE_LEN - 1);
    }

    // Set last element as NULL
    ret_arr[count] = NULL;

    for (int i = 0; ret_arr[i] != NULL; i++) {
        if (DEBUG >= 2) {
            printf("Line %d: %s\n", i, ret_arr[i]);
        }
    }

    // Free unused space
    for (int i = count + 1; i < MAX_ARR_SIZE; i++) {
        free(ret_arr[i]);
        ret_arr[i] = NULL;
    }

    // Shrink array size
    ret_arr = realloc(ret_arr, sizeof(char) * (count + 1));

    free(output);

    return ret_arr;
}