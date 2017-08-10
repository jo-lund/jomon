#ifndef MISC_H
#define MISC_H

// TODO: Clean up this file

#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <limits.h>

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

#ifdef PATH_MAX
#define MAXPATH PATH_MAX
#else
#define MAXPATH 1024
#endif

typedef struct {
    char *device;
    char filename[MAXPATH + 1];
    bool capturing;
    bool show_statistics;
} main_context;

extern struct sockaddr_in *local_addr;

void finish();
void stop_scan();
void start_scan();

#endif
