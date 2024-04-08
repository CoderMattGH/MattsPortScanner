/*
 * Returns a string representation of a MAC address.
 */
char * get_mac_str(const unsigned char* mac_add);

/*
 * Converts and IP address into a string.
 * Returns NULL on error.
*/
char * get_ip_str(struct in_addr *ip_add);

/*
 * Converts an IP string to an in_addr struct.  
 * Returns NULL on error.
 */
struct in_addr * get_ip_from_str(char *ip_str);

/*
 * Converts a MAC address string to a MAC address array.
 */
unsigned char * get_mac_from_str(char *mac_str);

/*
 * Gets the MAC address associated with the supplied interface name.
 * Returns NULL on error.
 */
unsigned char * get_mac_address(int* sock, char *dev_name);

/*
 * Gets the IP address associated with the supplied interface name.
 * Returns NULL on error.
 */
struct in_addr * get_ip_address(int *sock, char *dev_name);

/*
 * Allocates, zeros and returns an ifreq struct.
 */
struct ifreq * get_ifreq_struct(char *dev_name);

/*
 * Gets the interface index and returns it as an int.
 * Returns -1 on error. 
 */
int get_interface_index(int *sock, char *dev_name);