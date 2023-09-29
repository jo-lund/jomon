#ifndef BLUETOOTH_H
#define BLUETOOTH_H

struct interface;

/*
 * Find and store Bluetooth interfaces in struct interface. 'cap' is the capacity
 * of the list, i.e. the max number of interfaces that can be stored.
 *
 * Return the number of interfaces found.
 */
int bt_interfaces(struct interface *ifc, int cap);

#endif
