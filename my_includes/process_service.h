/*
 * Function: load_process
 * ----------------------
 * Loads a process from the path supplied and saves the output from the process
 * as a 2D char array.  
 * Each line of output is a row in the array.
 * 
 * path: The path to execute.
 * 
 * return: A 2d char array, or NULL on error.
 */
char ** load_process(const char* path);