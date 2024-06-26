#define ICMP_PACK_LENGTH 64     // 64 byte packet size

/*
 * Function: send_icmp_request
 * ---------------------------
 * Constructs and sends an ICMP packet
 * 
 * src_ip: Source IP address as a string
 * 
 * dst_ip: Destination IP address as a string
 * 
 * src_mac: Source MAC address represented as an array
 * 
 * dst_mac: Destination MAC address represented as an array
 * 
 * sock_raw: Raw Socket descriptor
 * 
 * inter_index: Interface index for the network device to use
 * 
 * returns: 0 on success, -1 on error.
 */
int send_icmp_request(const char* src_ip, const char* dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac, 
        int sock_raw, int inter_index);

/*
 * Function: ping_target
 * ---------------------
 * Sends an ICMP packet to the target IP address and waits for a reply.
 * NOTE: Timeout occurs after 7 seconds.
 * 
 * src_ip: Source IP address in array representation.
 * 
 * dst_ip: The target IP address in array representation.
 * 
 * src_mac: The source MAC address in array representation.
 * 
 * dst_mac: The destination MAC address in array representation.
 * 
 * sock_raw: The raw socket descriptor.
 * 
 * inter_index: The network interface index.
 * 
 * return: 1 indicates reply was received, 0 indicates reply timed out, -1
 *         indicates an error occurred.
 */
int ping_target(const unsigned char* src_ip, const unsigned char* dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac, 
        int sock_raw, int inter_index);

/*
 * Function: construct_icmp_packet
 * -------------------------------
 * Constructs an ICMP packet
 * 
 * src_ip: Source IP address as a string
 * 
 * dst_ip: Destination IP address as a string
 * 
 * src_mac: Source MAC address represented as a array
 * 
 * dst_mac: Destination MAC address represented as a array
 * 
 * returns: The constructed packet or NULL on error
 */
unsigned char * construct_icmp_packet(const char *src_ip, const char *dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac);

/*
 * Function: listen_for_icmp_response
 * ----------------------------------
 * Constructs a raw socket and listens for a ICMP response with the relevant
 * source MAC address, source IP address and destination IP address.
 * 
 * NOTE: Will timeout after 7 seconds.
 * 
 * loc_mac: The local MAC address represented as an array.
 * 
 * loc_ip: The local IP address represented as an array.
 * 
 * tar_ip: The target IP address represented as an array.
 * 
 * return: 1 if ICMP response was received, 0 if not, or -1 if error.
 */
int listen_for_icmp_response(const unsigned char *loc_mac, 
        const unsigned char *loc_ip, const unsigned char *tar_ip);