/*
 * TCP Pseudoheader used in calculating the TCP header checksum
 */
struct psheader {
    __be32 saddr;       // IP source address
    __be32 daddr;       // IP destination address
    __u8 reserved;      // Reserved bits (0)
    __u8 protocol;       // IP Protocol (6 = tcp)

    // Length of TCP segment (TCP header and data length). 
    // Normally 20 bytes with no data.
    __be16 tcpseglen;   
};

/*
 * Function: ip_checksum
 * ---------------------
 * Calculates the IP header checksum and returns the result.
 * Checksum is the 16 bit ones complement of the sum of all 16 bit words in the
 * IP header.
 * 
 * start_of_header: A pointer to the start of the IP header.
 * 
 * return: The checksum result.
 */
unsigned short ip_checksum(const unsigned short* start_of_header);

/*
 * Function: tcp_checksum
 * ----------------------
 * Calculates the TCP header checksum and returns the result.
 * NOTE: Does not currently accept payload data.
 * 
 * start_of_header: A pointer to the start of the TCP header.
 * 
 * start_of_pseudo_header: A pointer to the start of the pseudo header.
 * 
 * return: The checksum result.
 */
unsigned short tcp_checksum(const unsigned short* start_of_header, 
        const unsigned short *start_of_pseudo_header);

/*
 * Function: icmp_checksum
 * -----------------------
 * Calculates the ICMP header checksum and returns the result.
 * Checksum is the 16 bit ones complement of the sum of all 16 bit words in the
 * ICMP header.
 * Header length is 8 bytes without any payload data.
 * 
 * NOTE: Any payload data should be included in the sum.
 * 
 * start_of_header: a pointer to the start of the ICMP header.
 * 
 * return: The checksum result.
 */
unsigned short icmp_checksum(const unsigned short* start_of_header);

/*
 * Function: send_packet
 * ---------------------
 * Attempts to send a supplied packet on the network interface.
 * 
 * packet: A packet to send.
 * 
 * packet_len: Length of the packet.
 * 
 * socket: A raw socket descriptor.
 * 
 * dev_index: The network interface index.
 * 
 * mac_src: The source MAC address represented in array format.
 * 
 * return: Returns -1 on error, otherwise returns the number of bytes sent.
 */
int send_packet(const unsigned char *packet, int packet_len, int socket, 
        int dev_index, const unsigned char *mac_src);
