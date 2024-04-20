/*
 * Function: construct_syn_packet
 * ------------------------------
 * Constructs and populates a TCP IP SYN packet with no data payload.
 * 
 * src_ip: The source IP address represented as a string.
 * 
 * dst_ip: The destination IP address represented as a string.
 * 
 * src_mac: The source MAC address represented as an array.
 * 
 * dst_mac: The destination MAC address represented as an array.
 * 
 * src_port: The source port.
 * 
 * dst_port: The destination port.
 * 
 * return: A TCP IP SYN packet ready to send.
 */
unsigned char * construct_syn_packet(const char *src_ip, const char *dst_ip, 
        const unsigned char *src_mac, const unsigned char *dst_mac, 
        unsigned short int src_port, unsigned short int dst_port);

/*
 * Function: listen_for_ACK_replies
 * --------------------------------
 * Listens for ACK TCP packets which are destined for the src_mac address.
 * 
 * tar_ip: The target IP address represented in array format that the function
 *         will listen to replies from.
 * 
 * dest_mac: The MAC address we use to filter out unwanted packets not meant
 *           for this interface.
 * 
 * stop_listening: A variable indicating whether to stop listening for packets
 *                 and return.
 * 
 * return: A unsigned short int array of open ports or NULL on error or no ports
 *         found. errno is set to EIO(5) on error.
  */
unsigned short int * listen_for_ACK_replies(const unsigned char* tar_ip, 
        const unsigned char* dest_mac, unsigned char *stop_listening);