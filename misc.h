#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

/* 
 * Only a portion of each packet is passed by BPF to the application, this size is
 * the snapshot length or the snaplen.
 */
#define SNAPLEN 65535

/* 
 * Timeout value that decides when BPF copies its buffer to the application. A 
 * timeout value of 0 means that the application want it as soon as BPF receives 
 * the packet.
 */
#define TIME_TO_WAIT 0
 
static struct sockaddr_in *local_addr;
int verbose;
int promiscuous;
unsigned int num_packets_sent;
unsigned int num_packets_rcvd;
unsigned int bad_packets;
unsigned long tot_bytes_sent;
unsigned long tot_bytes_rcvd;

int check_ip(const u_char *bytes);
