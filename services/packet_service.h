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
