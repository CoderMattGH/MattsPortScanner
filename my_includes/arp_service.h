#define ARP_RQ_PSIZE 42         // ARP request packet size

/*
 * Constructs an ARP packet with the supplied parameters.
 */
unsigned char * make_arp_packet(unsigned char *src_mac, unsigned char *dst_mac, 
        unsigned char *src_ip, unsigned char *tar_ip);

/*
 * Broadcasts an ARP request to the local network.  
 * This will populate the ARP table on the client if the IP address exists on
 * the network.
 * Returns -1 on error.
 */
int send_arp_request(int sock_raw, unsigned char *src_mac, 
        unsigned char *src_ip, unsigned char *tar_ip, int dev_index);        