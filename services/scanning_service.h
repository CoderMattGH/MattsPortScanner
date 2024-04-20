// Time to sleep after finishing sending all the SYN packets
#define SLEEP_S_AFTER_FINISH 5

struct scan_port_args {
    struct in_addr *tar_ip;
    int start_port;
    int end_port;
};

struct scan_raw_port_args {
    const unsigned char *src_ip;
    const unsigned char *tar_ip;
    const unsigned char *src_mac;
    const unsigned char *tar_mac;
    int start_port;
    int end_port;
    int inter_index;
    unsigned char *finished;
};

struct scan_raw_arr_args {
    const unsigned char *src_ip;
    const unsigned char *tar_ip;
    const unsigned char *src_mac;
    const unsigned char *tar_mac;
    const unsigned short *ports;
    int ports_len;
    int inter_index;
    unsigned char *finished;    
};

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
 * return: An int array of open TCP port numbers.
 */
int * scan_ports_raw_multi(const unsigned char *src_ip,
        const unsigned char *tar_ip, const unsigned char *src_mac,
        const unsigned char *tar_mac, int start_port, int end_port, 
        int inter_index);

/*
 * Function: scan_ports_raw_arr_multi
 * ----------------------------------
 * Scans the ports specified in the ports array in a multithreaded manner using 
 * raw sockets, which reduces the number of retransmissions and thus increases
 * speed and lowers bandwidth.
 * 
 * src_ip: The source IP address in array format.
 * 
 * tar_ip: The target IP address in array format.
 * 
 * src_mac: The source MAC address in array format.
 * 
 * tar_mac: The target MAC address in array format.
 * 
 * ports: The ports to scan in an unsigned short array.
 * 
 * ports_len: The length of the ports array.
 * 
 * inter_index: The network interface number.
 * 
 * return: An integer array of open TCP port numbers.
 */
int * scan_ports_raw_arr_multi(const unsigned char *src_ip, 
        const unsigned char *tar_ip, const unsigned char *src_mac,
        const unsigned char *tar_mac, const unsigned short *ports, 
        int ports_len, int inter_index);

/*
 * Function: scan_ports_raw_arr_proxy
 * ----------------------------------
 * A proxy function for scan_ports_raw_arr().  Primary purpose is to facilitate
 * calling scan_ports_raw_arr() from a new thread.
 * 
 * scan_args: A struct scan_raw_arr_args structure cast as (void *).
 * 
 * return: Void
 */
void * scan_ports_raw_arr_proxy(void *scan_args);

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
* return: an integer with 0 representing success and -1 as error.
 */
int scan_ports_raw(const unsigned char *src_ip, const unsigned char *tar_ip, 
        const unsigned char *src_mac, const unsigned char *tar_mac,
        int start_port, int end_port, int inter_index);

/*
 * Function: scan_ports_raw_arr
 * ----------------------------
 * Scans the ports contained in the array sent as a function parameter. 
 * 
 * src_ip: The source IP address in array format.
 * 
 * tar_ip: The target IP address in array format.
 * 
 * src_mac: The source MAC address.
 * 
 * tar_mac: The target MAC address.
 * 
 * ports: The TCP port numbers to scan.
 * 
 * ports_len: The length of the ports array.
 * 
 * start_port: The port to start scanning from.
 * 
 * end_port: The port to end scanning at.
 * 
 * inter_index: The network interface index.
 * 
 * return: an integer with 0 representing success and -1 as error.
 */
int scan_ports_raw_arr(const unsigned char *src_ip,
        const unsigned char *tar_ip, const unsigned char *src_mac,
        const unsigned char *tar_mac, const unsigned short *ports,
        int ports_len, int inter_index);

/*
 * Function: get_random_port_num
 * -----------------------------
 * Returns a random number between 1000 and MAX_PORT (65535).
 * 
 * Return: An unsigned short int between 1000 and MAX_PORT.
 */
unsigned short int get_random_port_num();