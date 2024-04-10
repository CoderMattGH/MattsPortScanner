/*
 * Returns a string representation of a MAC address.
 */
char * get_mac_str(const unsigned char* mac_add);

/*
 * Converts and IP address into a string.
 * Returns NULL on error.
*/
char * get_ip_str(const struct in_addr *ip_add);

/*
 * Converts an IP address represented as an array into a string.
 */
char * get_ip_arr_str(const unsigned char *ip_add);

/*
 * Converts an IP string to an in_addr struct.  
 * Returns NULL on error.
 */
struct in_addr * get_ip_from_str(const char *ip_str);

/*
 * Converts a MAC address string to a MAC address array.
 */
unsigned char * get_mac_from_str(const char *mac_str);

/*
 * Gets the MAC address associated with the supplied interface name.
 * Returns NULL on error.
 */
unsigned char * get_mac_address(const int* sock, const char *dev_name);

/*
 * Gets the IP address associated with the supplied interface name.
 * Returns NULL on error.
 */
struct in_addr * get_ip_address(const int *sock, const char *dev_name);

/*
 * Allocates, zeros and returns an ifreq struct.
 */
struct ifreq * get_ifreq_struct(const char *dev_name);

/*
 * Gets the interface index and returns it as an int.
 * Returns -1 on error. 
 */
int get_interface_index(const int *sock, const char *dev_name);

/*
 *  Get IP address as a char array.
 */
unsigned char * get_ip_arr_rep(const struct in_addr *ip_add);

/**
 * Returns the default gateway IP address of the supplied interface. 
 * 
 * @dev_name: The network interface name.
 * @return: An IP address or NULL on error.
 */
struct in_addr * get_gw_ip_address(const char *dev_name);