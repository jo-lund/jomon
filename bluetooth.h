#ifndef BLUETOOTH_H
#define BLUETOOTH_H

#include "interface.h"

/*
 * Find and store Bluetooth interfaces in struct interface. 'cap' is the capacity
 * of the list, i.e. the max number of interfaces that can be stored.
 *
 * Return the number of interfaces found.
 */
int bt_interfaces(struct interface *ifc, int cap);

/* Create a Bluetooth interface handle */
iface_handle_t *iface_bt_create(char *dev, unsigned char *buf, size_t len, packet_handler fn);

#endif
