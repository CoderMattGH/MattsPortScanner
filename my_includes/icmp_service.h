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