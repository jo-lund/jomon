/* Network traffic monitor
 *
 * This program will monitor all incoming/outgoing network traffic and 
 * print out the speed of the download/upload. It uses the libpcap library, 
 * if available, to capture packets (http://www.tcpdump.org). On Mac OS X this
 * library will use the BSD packet filter (BPF) to interface with the network
 * device.
 *
 * The speed of the download/upload is based on the network throughput, which
 * means that the bit rate will be measured at a reference point above the 
 * datalink layer, i.e., the reference point will be the IP layer.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#ifdef MACOS
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#ifdef linux
#include <netpacket/packet.h>
#endif
#include "misc.h"
#include "error.h"
#include "interface.h"
#if 0
#include "pcap_handler.h"
#endif

static linkdef rx; /* data received */
static linkdef tx; /* data transmitted */
struct sockaddr_in *local_addr;
int verbose;
int promiscuous;
int capture;

void print_help(char *prg);
void get_local_address(char *dev, struct sockaddr *addr);
int init(char **device);
void read_packets(int fd);
void print_rate();
void sig_alarm(int signo);

int main(int argc, char **argv)
{
    char *device = NULL;
    char *prg_name = argv[0];
    int opt;
    int fd;

    capture = 0;
    promiscuous = 0;
    while ((opt = getopt(argc, argv, "i:lhvpc")) != -1) {
        switch (opt) {
        case 'i':
            device = optarg;
            break;
        case 'l':
            list_interfaces();
            exit(0);
            break;
        case 'p':
            promiscuous = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'c':
            capture = 1;
            break;
        case 'h':
        default:
            print_help(prg_name);
            exit(1);
        }
    }

#if 0
    // need proper closing of resources. Make a signal.
    init_pcap(device);
    //pcap_close(pcap_handle);
#endif

#ifdef linux
    fd = init(&device);
    local_addr = malloc(sizeof(local_addr));
    get_local_address(device, (struct sockaddr *) local_addr);
    if (verbose) {
        char addr[INET_ADDRSTRLEN];

        printf("Listening on device: %s  ", device);
        inet_ntop(AF_INET, &local_addr->sin_addr, addr, sizeof(addr));
        printf("Local address: %s\n\n", addr);
    }
    read_packets(fd);
    free(device);
    free(local_addr);
#endif
}

void print_help(char *prg)
{
    printf("Usage: %s [-lvhp] [-i interface]\n", prg);
    printf("Options:\n");
    printf("     -i  Specify network interface\n");
    printf("     -l  List available interfaces\n");
    printf("     -p  Use promiscuous mode\n");
    printf("     -c  Capture and print packets\n");
    printf("     -v  Print verbose information\n"); 
    printf("     -h  Print this help summary\n");
}

void get_local_address(char *dev, struct sockaddr *addr)
{
    struct ifreq ifr;
    int sockfd;

    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
    ifr.ifr_addr.sa_family = AF_INET;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        err_sys("socket error");
    }
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        err_sys("ioctl error");
    }
    memcpy(addr, &ifr.ifr_addr, sizeof(*addr));
}

/* Initialize device and prepare for reading */
int init(char **device)
{
    int sockfd;
    struct sockaddr_ll ll_addr; /* device independent physical layer address */
    struct sigaction act, oact;

    if (!*device) {
        if (!(*device = get_default_interface())) {
            err_quit("Cannot find active network device\n");
        }
    }

    if (capture) {
        /* SOCK_RAW packet sockets include the link level header */
        if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
            err_sys("socket error");
        }
    } else {
        /* SOCK_DGRAM are cooked packets with the link level header removed */
        if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) == -1) {
            err_sys("socket error");
        }
    }
    setuid(getuid()); /* no need for root access anymore */
    memset(&rx, 0, sizeof(linkdef));
    memset(&tx, 0, sizeof(linkdef));
    memset(&ll_addr, 0, sizeof(ll_addr));
    ll_addr.sll_protocol = htons(ETH_P_ALL);
    ll_addr.sll_ifindex = htonl(get_interface_index(*device));

    /* only receive packets on the specified interface */
    bind(sockfd, (struct sockaddr *) &ll_addr, sizeof(ll_addr));

    /* set up an alarm signal handler */
    act.sa_handler = sig_alarm;
    sigemptyset(&act.sa_mask);
    act.sa_flags |= SA_RESTART;
    if (sigaction(SIGALRM, &act, &oact) == -1) {
        err_sys("sigaction error");
    }

    return sockfd;
}

void print_rate()
{
    int rxmbytes = rx.tot_bytes / (1024 * 1024); 
    int txmbytes = tx.tot_bytes / (1024 * 1024);
    double rxmbitspsec = rx.kbps / 1024 * 8;
    double txmbitspsec = tx.kbps / 1024 * 8;

    if (verbose) {
        printf("\rRX: %5.0f KB/s (%3.1f Mbit/s) %8ld b (%d Mb) %d packets",
               rx.kbps, rxmbitspsec, rx.tot_bytes, rxmbytes, rx.num_packets);
    } else {
        printf("\rRX: %5.0f KB/s (%3.1f Mbit/s)\tTX: %5.0f KB/s (%3.1f Mbit/s)", 
               rx.kbps, rxmbitspsec, tx.kbps, txmbitspsec);
    }
    fflush(stdout);
}

void read_packets(int sockfd)
{
    char buffer[SNAPLEN];
    int n;
    struct iphdr *ip;
    char srcaddr[INET_ADDRSTRLEN];
    char dstaddr[INET_ADDRSTRLEN];

    memset(buffer, 0, SNAPLEN);
    alarm(1);
    while (1) {
        print_rate();
        if ((n = read(sockfd, buffer, SNAPLEN)) == -1) {
            err_sys("read error");
        }
        ip = (struct iphdr *) buffer;
        if (inet_ntop(AF_INET, &ip->saddr, srcaddr, INET_ADDRSTRLEN) == NULL) {
            err_msg("inet_ntop error");
        }
        if (inet_ntop(AF_INET, &ip->daddr, dstaddr, INET_ADDRSTRLEN) == NULL) {
            err_msg("inet_ntop error");
        }
        //printf("%s -> %s\n", srcaddr, dstaddr);
        if (memcmp(&ip->saddr, &local_addr->sin_addr, sizeof(ip->saddr)) == 0) {
            tx.num_packets++;
            tx.tot_bytes += ntohs(ip->tot_len);
        }
        if (memcmp(&ip->daddr, &local_addr->sin_addr, sizeof(ip->daddr)) == 0) {
            rx.num_packets++;
            rx.tot_bytes += ntohs(ip->tot_len);
        }
    }
}

void sig_alarm(int signo)
{
    rx.kbps = (rx.tot_bytes - rx.prev_bytes) / 1024;
    tx.kbps = (tx.tot_bytes - tx.prev_bytes) / 1024;
    rx.prev_bytes = rx.tot_bytes;
    tx.prev_bytes = tx.tot_bytes;
    alarm(1);
}
