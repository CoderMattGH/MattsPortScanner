/*
 * Function: scan_ports_multi
 * --------------------------
 * Scans the port range in a multithreaded manner.
 * 
 * tar_ip: Target IP address.
 * 
 * start_port: Start of port range to scan.
 * 
 * end_port: End of port range to scan.
 * 
 * returns: An int array representing ports that are open (1) or closed(0).
 *          NULL on error.
 */
int * scan_ports_multi(struct in_addr *tar_ip, int start_port, int end_port);

/*
 * Function: scan_ports_raw_multi
 * ------------------------------
 * Scans the port range in a multithreaded manner using raw sockets, which
 * reduces the number of retransmissions and thus increases speed and lowers
 * bandwidth.
 * 
 * src_ip: The source IP address in array format.
 * 
 * tar_ip: The target IP address in array format.
 * 
 * src_mac: The source MAC address in array format.
 * 
 * tar_mac: The target MAC address in array format.
 * 
 * start_port: The starting port of the range to scan.
 * 
 * end_port: The end port of the range to scan.
 * 
 * inter_index: The network interface index.
 * 
 * returns: An int array representing ports that are open (1) or closed(0).
 *          NULL on error.
 */
int * scan_ports_raw_multi(const unsigned char *src_ip,
        const unsigned char *tar_ip, const unsigned char *src_mac,
        const unsigned char *tar_mac, int start_port, int end_port, 
        int inter_index);

/*
 * Function: scan_ports_proxy
 * --------------------------
 * A proxy function for scan_ports().  Primary purpose is to facilitate calling
 * scan_ports() from a new thread.
 * 
 * scan_args: A struct scan_port_args structure cast as (void *).
 * 
 * return: Void.
 */
void * scan_ports_proxy(void *scan_args);

/*
 * Function: scan_ports
 * --------------------
 * Scans the range of ports from start_port to end_port on the specified
 * target IP address.
 * 
 * tar_ip: The target IP address.
 * 
 * start_port: The port to start scanning at.
 * 
 * end_port: The port to end scanning at.
 * 
 * return: Returns an int array of size (MAX_PORT + 1).  The array index
 * pertains to the port number where a 1 indicates open and 0 indicates closed.
 * Or NULL on error.
 */
int * scan_ports(struct in_addr *tar_ip, int start_port, int end_port);

/*
 * Function: scan_ports_raw_proxy
 * ------------------------------
 * A proxy function for scan_ports_raw().  Primary purpose is to facilitate
 * calling scan_ports_raw() from a new thread.
 * 
 * scan_args: A struct scan_port_raw_args structure cast as (void *).
 * 
 * return: Void.
 */
void * scan_ports_raw_proxy(void *scan_args);

/*
 * Function: scan_ports_raw
 * ------------------------
 * Scans the range of ports from start_port to end_port on the specified target
 * target IP address.
 * 
 * src_ip: The source IP address in array format.
 * 
 * tar_ip: The target IP address in array format.
 * 
 * src_mac: The source MAC address in array format.
 * 
 * tar_mac: The target MAC address in array format.
 * 
 * start_port: The port to start scanning from.
 * 
 * end_port: The port to end scanning at.
 * 
 * inter_index: The network interface index.
 * 
 * return: Returns an int array of size (MAX_PORT + 1).  The array index
 * pertains to the port number where a 1 indicates open and 0 indicates closed.
 * Or NULL on error.
 */
int * scan_ports_raw(const unsigned char *src_ip, const unsigned char *tar_ip, 
        const unsigned char *src_mac, const unsigned char *tar_mac,
        int start_port, int end_port, int inter_index);

/*
 * Function: get_random_port_num
 * -----------------------------
 * Returns a random number between 1000 and MAX_PORT (65535).
 * 
 * Return: An unsigned short int between 1000 and MAX_PORT.
 */
unsigned short int get_random_port_num();