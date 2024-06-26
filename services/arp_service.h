#include "../constants/constants.h"

// ARP request packet size
#define ARP_RQ_PSIZE 42         

// Construct the ARP payload
struct arp_payload {
    unsigned char src_mac[MAC_LEN];
    unsigned char src_ip[IP_LEN];
    unsigned char tar_mac[MAC_LEN];
    unsigned char tar_ip[IP_LEN];
};

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
unsigned char * make_arp_packet(const unsigned char *src_mac, 
        const unsigned char *dst_mac, const unsigned char *src_ip, 
        const unsigned char *tar_ip);

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
int send_arp_request(int sock_raw, const unsigned char *src_mac, 
        const unsigned char *src_ip, const unsigned char *tar_ip, 
        int dev_index);        

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
char * search_arp_table(const char *ip_address);

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
unsigned char * get_mac_add_from_ip(const unsigned char *tar_ip, int sock_raw, 
        const unsigned char *src_mac, const unsigned char *src_ip, 
        int dev_index, const char* dev_name);

/*
 * Function: listen_for_arp_response
 * ---------------------------------
 * Listens for a ARP reply (op-code 2) for the target IP address.
 * NOTE: Function will timeout after 7 seconds.
 * 
 * loc_mac: The local MAC address in array format.
 * 
 * loc_ip: The local IP address in array format.
 * 
 * tar_ip: The target IP address in array format.
 * 
 * return: Returns the target MAC address on success or NULL on failure or 
 *         error.
 */
unsigned char * listen_for_arp_response(const unsigned char *loc_mac, 
        const unsigned char *loc_ip, const unsigned char *tar_ip);