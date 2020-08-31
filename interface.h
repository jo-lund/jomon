#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "bpf/bpf.h"

struct iw_statistics;
struct iw_range;

typedef bool (*packet_handler)(unsigned char *buffer, uint32_t n, struct timeval *t);

typedef struct iface_handle {
    int sockfd;
    packet_handler on_packet;
    unsigned char *buf;
    size_t len;
    bool active;
    struct iface_operations *op;
} iface_handle_t;

struct iface_operations {
    void (*activate)(iface_handle_t *handle, char *device, struct bpf_prog *bpf);
    void (*close)(iface_handle_t *handle);
    void (*read_packet)(iface_handle_t *handle);
};

/* Create a new interface handle */
iface_handle_t *iface_handle_create();

/* Activate the interface */
void iface_activate(iface_handle_t *handle, char *device, struct bpf_prog *bpf);

/* Close the interface */
void iface_close(iface_handle_t *handle);

/*
 * Read a packet from the network interface card. The iface_handle on_packet
 * callback is called for each packet.
 */
void iface_read_packet(iface_handle_t *handle);

/* Print all interfaces */
void list_interfaces();

/* Return the first interface which is up and running */
char *get_default_interface();

/* get the interface number associated with the interface (name -> if_index mapping) */
int get_interface_index(char *dev);

/* get the local IP address */
void get_local_address(char *dev, struct sockaddr *addr);

/* get the local MAC address */
void get_local_mac(char *dev, unsigned char *mac);

/* get wireless statistics */
bool get_iw_stats(char *dev, struct iw_statistics *iwstat);
bool get_iw_range(char *dev, struct iw_range *iwrange);

/* Enable/disable promiscuous mode */
void set_promiscuous(char *dev, bool enable);

#endif
