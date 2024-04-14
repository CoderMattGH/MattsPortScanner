/*
 * Function: validate_ip_str
 * -------------------------
 * Validates a IPv4 address string.
 * 
 * ip_str: The string representation of an IPv4 IP address.
 * 
 * return: A boolean value indicating true (1) as success or false (0) if 
 *         validation failed.
 */
unsigned char validate_ip_str(const char *ip_str);

/*
 * Function: validate_ip_arr
 * -------------------------
 * Validates a IPv4 address in array representation.
 * 
 * ip_arr: The array representation of an IPv4 address.
 * 
 * return: A boolean value indicating true (1) on success or false (0) if 
 *         validation failed.
 */
unsigned char validate_ip_arr(const unsigned char *ip_arr);

/*
 * Function: validate_ip_add
 * -------------------------
 * Validates a IPv4 address.
 * 
 * ip_add: The IPv4 address.
 * 
 * return: A boolean value indicating true(1) on success or false (0) if
 *         validation failed.
 */
unsigned char validate_ip_add(struct in_addr* ip_add);