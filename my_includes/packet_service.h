/*
 * Calculates the IP header checksum and returns the result.
 * Checksum is the 16 bit ones complement of the sum of all 16 bit words in the
 * IP header.
 * Takes as a parameter a pointer to the start of the IP header.
 */
unsigned short ip_checksum(unsigned short* start_of_header);

/*
 * Calculates the ICMP header checksum and returns the result.
 * Checksum is the 16 bit ones complement of the sum of all 16 bit words in the
 * ICMP header.
 * Header length is 8 bytes without any payload data.
 * Takes as a parameter a pointer to the start of the ICMP header.
 * NOTE: Any payload data should be included in the sum.
 */
unsigned short icmp_checksum(unsigned short* start_of_header);

/*
 * Attempts to send a supplied packet using the supplied parameters.
 * Returns -1 on error otherwise returned the length in bytes sent.
 */
int send_packet(unsigned char* packet, int packet_len, int socket, 
        int dev_index, unsigned char* mac_src);

