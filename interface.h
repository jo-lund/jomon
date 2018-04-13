#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdbool.h>
#ifdef __linux__
#include <linux/wireless.h>
#endif

/* Print all interfaces */
void list_interfaces();

/* Return the first interface which is up and running */
char *get_default_interface();

/* Get the interface number associated with the interface (name -> if_index mapping) */
int get_interface_index(char *dev);

/* Get the local IP address */
void get_local_address(char *dev, struct sockaddr *addr);

/* Get wireless statistics */
bool get_iw_stats(char *dev, struct iw_statistics *iwstat);

bool get_iw_range(char *dev, struct iw_range *iwrange);

/* Set wireless operation mode */
void set_iw_mode(char *dev, int mode);

#endif
