#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdbool.h>

struct iw_statistics;

/* Print all interfaces */
void list_interfaces();

/* Return the first interface which is up and running */
char *get_default_interface();

/* get the interface number associated with the interface (name -> if_index mapping) */
int get_interface_index(char *dev);

/* get the local IP address */
void get_local_address(char *dev, struct sockaddr *addr);

/* get wireless statistics */
bool get_iw_stats(char *dev, struct iw_statistics *iwstat);

#endif
