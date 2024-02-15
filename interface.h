#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "bpf/bpf.h"

#define IF_NAMESIZE 16
#define IF_HWADDRLEN 8
#define LINKTYPE_ETHERNET 1
#define LINKTYPE_IEEE802 6   /* IEEE 802.2 Ethernet/Token Ring/Token Bus */
#define LINKTYPE_BT_HCI_H4 187  /* Bluetooth HCI UART transport layer */
#define LINKTYPE_BT_HCI_H4_WITH_PHDR 201  /* Bluetooth HCI UART transport layer */

struct timeval;
struct iface_handle;

typedef bool (*packet_handler)(struct iface_handle *handle, unsigned char *buffer,
                               uint32_t n, struct timeval *t);

typedef struct iface_handle {
    int fd;
    packet_handler on_packet;
    unsigned char *buf;
    size_t len;
    bool active;
    bool use_zerocopy;
    unsigned int linktype;         /* interface type, e.g. Ethernet, Firewire etc. */
    char device[IF_NAMESIZE];      /* interface name */
    unsigned char mac[IF_HWADDRLEN];
    struct sockaddr_in inaddr;     /* IPv4 address */
    struct sockaddr_in6 in6addr;   /* IPv6 address */
    struct iface_operations *op;
    void *data;  /* implementation specific data */
} iface_handle_t;

struct iface_operations {
    void (*activate)(iface_handle_t *handle, struct bpf_prog *bpf);
    void (*close)(iface_handle_t *handle);
    void (*read_packet)(iface_handle_t *handle);
    void (*set_promiscuous)(iface_handle_t *handle, bool enable);
    void (*get_mac)(iface_handle_t *handle);
    void (*get_address)(iface_handle_t *handle);
};

struct interface {
    char name[IF_NAMESIZE];        /* interface name */
    unsigned short type;           /* interface type, e.g. Ethernet, Firewire etc. */
    struct sockaddr_in *inaddr;    /* IPv4 address */
    struct sockaddr_in6 *in6addr;  /* IPv6 address */
    unsigned char addrlen;         /* hardware address length */
    unsigned char hwaddr[8];       /* hardware address */
};

/* Create a new interface handle */
iface_handle_t *iface_handle_create(char *dev, unsigned char *buf, size_t len,
                                    packet_handler fn);

/* Activate the interface */
void iface_activate(iface_handle_t *handle, struct bpf_prog *bpf);

/* Close the interface */
void iface_close(iface_handle_t *handle);

/*
 * Read a packet from the network interface card. The iface_handle on_packet
 * callback is called for each packet.
 */
void iface_read_packet(iface_handle_t *handle);

/* Enable/disable promiscuous mode */
void iface_set_promiscuous(iface_handle_t *handle, bool enable);

/* Get the interface MAC address */
void iface_get_mac(iface_handle_t *handle);

/* Get the interface IP address */
void iface_get_address(iface_handle_t *handle);

/* Print all interfaces */
void list_interfaces(void);

/* Check if the interface is wireless */
bool is_wireless(char *dev);

#endif
