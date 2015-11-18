/* Print all interfaces */
void list_interfaces();

/* Return the first interface which is up and running */
char *get_default_interface();

/* get the interface number associated with the interface (name -> if_index mapping) */
int get_interface_index(char *dev);
