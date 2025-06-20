#ifndef JOMON_H
#define JOMON_H

#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <limits.h>
#include "debug.h"
#include "util.h"
#include "string.h"
#include "attributes.h"
#include "error.h"
#include "wrapper.h"
#include "attributes.h"
#include "interface.h"

/*
 * Only a portion of each packet is passed by the kernel to the application, this
 * size is the snapshot length or the snaplen.
 */
#define SNAPLEN 65535

/*
 * Timeout value that decides when BPF copies its buffer to the application. A
 * timeout value of 0 means that the application wants it as soon as BPF receives
 * the packet.
 */
#define TIME_TO_WAIT 0

#define MAXLINE 1000
#define PACKET_TABLE_SIZE 65536

#ifdef PATH_MAX
#define MAXPATH PATH_MAX
#else
#define MAXPATH 1024
#endif

#define HEX_PRINT_MODES 2
#define HEX_PRINT_DGRAM 1
#define HEX_PRINT_LINK_LEVEL 2

typedef struct {
    char *device;
    char filename[MAXPATH];
    bool capturing;
    struct options {
        bool show_statistics;
        bool text_mode;
        bool nopromiscuous;
        bool verbose;
        bool load_file;
        bool numeric;
        bool no_domain;
        int dmode;
        int buffer_size;
        bool show_count;
        int hexmode;
        int hex_asciimode;
    } opt;
    bool nogeoip;
    struct sockaddr_in *local_addr;
    unsigned char mac[ETHER_ADDR_LEN];
    char *filter;
    char *filter_file;
    iface_handle_t *handle;
    bool pcap_saved;
    uint32_t packet_count;
} main_context;

extern main_context ctx;

void jomon_exit(int status) NORETURN;
void stop_capture(void);
void start_capture(void);

#endif
