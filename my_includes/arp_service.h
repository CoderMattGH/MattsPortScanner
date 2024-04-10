#define ARP_RQ_PSIZE 42         // ARP request packet size

/*
 * Function: make_arp_packet
 * -------------------------
 * Constructs an ARP packet.
 * 
 * src_mac: Source MAC address represented in array format.
 * 
 * dst_mac: Destination MAC address represented in array format.
 * 
 * src_ip: A source IP address represented in array format.
 * 
 * tar_ip: A target IP address represented in array format.
 */
unsigned char * make_arp_packet(unsigned char *src_mac, unsigned char *dst_mac, 
        unsigned char *src_ip, unsigned char *tar_ip);

/*
 * Function: send_arp_request
 * --------------------------
 * Broadcasts an ARP request to the local network.  
 * This will populate the ARP table on the client if the IP address exists on
 * the network.
 * 
 * sock_raw: A raw socket descriptor.
 * 
 * src_mac: A source MAC address represented in array format.
 * 
 * src_ip: A source IP address represented in array format.
 * 
 * tar_ip: A target IP address represented in array format.
 * 
 * dev_index: The interface device index.
 * 
 * return: Returns 0 on success, -1 on error.
 */
int send_arp_request(int sock_raw, unsigned char *src_mac, 
        unsigned char *src_ip, unsigned char *tar_ip, int dev_index);        

/* 
 * Function: search_arp_table
 * -------------------------- 
 * Queries the ARP table to get the assigned MAC address of the IP.
 *
 * ip_address: A string representation of an IP address.
 * 
 * return: A string representation of the MAC address in the form or NULL if
 *         not found.
 *         
*/
char * search_arp_table(char *ip_address);

/*
 * Function: get_mac_add_from_ip
 * -----------------------------
 * Returns the MAC address associated with the IP address.  If an IP address
 * cannot be found in the table, then the default gateway MAC address is
 * returned instead.
 * 
 * tar_ip: An array representation of an IPv4 address to search for.
 * 
 * sock_raw: Raw socket descriptor.
 * 
 * src_mac: Source MAC address in array format.
 * 
 * src_ip: Source IPv4 address in array format.
 * 
 * dev_index: An integer representing the local network interface id.
 * 
 * dev_name: Local network interface name.
 * 
 * return: Returns the MAC address found in array format, or NULL if not found
 *         or error.
 */
unsigned char * get_mac_add_from_ip(unsigned char *tar_ip, int sock_raw, 
        unsigned char *src_mac, unsigned char *src_ip, int dev_index, 
        char* dev_name);