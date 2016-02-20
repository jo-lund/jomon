#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

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

/* RX/TX variables */
typedef struct {
    unsigned long tot_bytes;
    unsigned long prev_bytes;
    unsigned int num_packets;
    unsigned int bad_packets;
    double kbps; /* kilobytes received per second */
} linkdef;

extern struct sockaddr_in *local_addr;
extern int verbose;
extern int promiscuous;
extern int capture;
extern linkdef rx; /* data received */
extern linkdef tx; /* data transmitted */
extern char *device;

int check_ip(const u_char *bytes);
