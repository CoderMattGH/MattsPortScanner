/*
 * Function: validate_port
 * -----------------------
 * Validates the supplied TCP port.
 * 
 * port: The TCP port.
 * 
 * return: 0 if invalid and 1 if valid.
 */
int validate_port(unsigned short port);

/*
 * Function: validate_port_range
 * -----------------------------
 * Validates the supplied TCP port range.
 * 
 * start_port: The starting TCP port.
 * 
 * end_port: The end TCP port.
 * 
 * return: 0 if range is invalid and 1 if valid.
 */
int validate_port_range(unsigned short start_port, unsigned short end_port);