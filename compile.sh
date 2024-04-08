#!/bin/bash

gcc portscanner.c ./my_includes/network_helper.c ./my_includes/packet_service.c -o portscanner
