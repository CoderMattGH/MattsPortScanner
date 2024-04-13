/*
 * Struct: input_args
 * ------------------
 * A struct to represent program parameters.
 * 
 * tar_ip: Target IP address.
 * 
 * dev_name: Network interface device name.
 * 
 * simp_scan: Boolean indicating to perform a simple scan or a full scan.
 * 
 * start_port: Starting TCP port.
 * 
 * end_port: Ending TCP port.
 */
struct input_args {
    const struct in_addr *tar_ip;    
    const char* dev_name;           
    unsigned char simp_scan;        
    unsigned short start_port;      
    unsigned short end_port;        
};

/*
 * Function: parse_input_args
 * --------------------------
 * Parses the input arguments and uses them to populate a input_args struct
 * used to set program options.
 *
 * argc: The number of tokens in argv.
 * 
 * argv: An array of tokens of size argc.
 * 
 * return: A input_args struct or NULL on error.
 */
struct input_args * parse_input_args(int argc, const char **argv);

/*
 * Function: print_usage
 * ---------------------
 * Prints the program's usage message.
 */
void print_usage();