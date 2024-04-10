/*
 * Function: get_mac_str
 * ---------------------
 * Returns a string representation of a MAC address.
 * 
 * mac_add: A MAC address represented in array format.
 * 
 * return: A string representation of a MAC address or NULL on error.
 */
char * get_mac_str(const unsigned char* mac_add);

/*
 * Function: get_ip_str
 * --------------------
 * Converts an IP address into a string.
 * 
 * ip_add: IP address to convert.
 * 
 * return: Returns a string representation of the IP address or NULL on error.
*/
char * get_ip_str(const struct in_addr *ip_add);

/*
 * Function: get_ip_arr_str
 * ------------------------
 * Converts an IP address represented as an array into a string.
 * 
 * ip_add: IP address represented in array format.
 * 
 * return: Returns a string representation of the IP address or NULL on error
 */
char * get_ip_arr_str(const unsigned char *ip_add);

/*
 * Function: get_ip_from_str
 * -------------------------
 * Converts an IP string to an in_addr struct.  
 * 
 * ip_str: An IP address represented as a string.
 * 
 * return: Returns the converted IP address or NULL on error.
 */
struct in_addr * get_ip_from_str(const char *ip_str);

/*
 * Function: get_mac_from_str
 * --------------------------
 * Converts a MAC address string to a MAC address array.
 * 
 * mac_str: A string representing a MAC address.
 * 
 * return: A MAC address in array format, or NULL on error.
 */
unsigned char * get_mac_from_str(const char *mac_str);

/*
 * Function: get_mac_address
 * -------------------------
 * Gets the MAC address associated with the supplied interface name.
 * 
 * sock: A socket descriptor.
 * 
 * dev_name: The network interface name.
 * 
 * return: A MAC address in array format, or NULL on error.
 */
unsigned char * get_mac_address(const int* sock, const char *dev_name);

/*
 * Function: get_ip_address
 * ------------------------
 * Gets the IP address associated with the supplied interface name.
 * 
 * sock: A socket descriptor.
 * 
 * dev_name: The network interface name.
 * 
 * return: Returns an IP address, or NULL on error.
 */
struct in_addr * get_ip_address(const int *sock, const char *dev_name);

/*
 * Function: get_ifreq_struct
 * --------------------------
 * Allocates, zeros and returns an ifreq struct.
 * 
 * dev_name: The network interface name.
 * 
 * return: Returns a newly allocated ifreq struct.
 */
struct ifreq * get_ifreq_struct(const char *dev_name);

/*
 * Function: get_interface_index
 * -----------------------------
 * Gets the interface index and returns it as an int.
 * 
 * sock: A socket descriptor.
 * 
 * dev_name: The network interface name.
 * 
 * return: An integer representing the device index.
 */
int get_interface_index(const int *sock, const char *dev_name);

/*
 * Function: get_ip_arr_rep
 * ------------------------
 * Gets IP address in array representation.
 * 
 * ip_add: The IP address to convert.
 * 
 * return: An array representation of the IP address, or NULL on error.
 */
unsigned char * get_ip_arr_rep(const struct in_addr *ip_add);

/*
 * Function: get_gw_ip_address
 * ---------------------------
 * Returns the default gateway IP address of the supplied interface. 
 * 
 * dev_name: The network interface name.
 * 
 * return: An IP address or NULL on error.
 */
struct in_addr * get_gw_ip_address(const char *dev_name);

/*
 * Function: get_ip_32_str
 * -----------------------
 * Converts an IP address represented as a 32 bit unsigned int into an array
 * representation.
 * 
 * ip_add: IP address.
 * 
 * return: An IP address represented as an array.
 */
unsigned char * get_ip_32_arr(unsigned int ip_add);

/*
 * Function: get_ip_32_str
 * -----------------------
 * Converts an IP address represented as a 32 bit unsigned int into a string.
 * 
 * ip_add: IP address.
 * 
 * return: An IP address string.
 */
char * get_ip_32_str(unsigned int ip_add);

/*
 * Function: compare_ip_add
 * ------------------------
 * Compares 2 IP addresses.
 * 
 * ip_add_a: IP address A represented as a array.
 * 
 * ip_add_b: IP address B represented as a array.
 * 
 * return: 0 if the two addresses are equal, or -1 if not equal.
 */
char * compare_ip_add(const unsigned char *ip_add_a, 
        const unsigned char *ip_add_b);

/*
 * Function: compare_mac_add
 * -------------------------
 * Compares 2 MAC addresses.
 * 
 * mac_add_a: MAC address A represented as a array.
 * 
 * mac_add_b: MAC address B represented as a array.
 * 
 * return: 0 if the two addresses are equal, or -1 if not equal.
 */
char * compare_mac_add(const unsigned char *mac_add_a,
        const unsigned char *mac_add_b);