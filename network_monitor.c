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
#ifdef MACOS
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#ifdef linux
#include <net/if_arp.h>
#include <netpacket/packet.h>
#endif
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include "misc.h"
#include "error.h"
#if 0
#include "pcap_handler.h"
#endif

#define MAX_NUM_INTERFACES 16

struct interface {
    char *name;                    /* interface name */
    unsigned short type;           /* interface type, e.g. Ethernet, Firewire etc. */
    struct sockaddr_in *inaddr;    /* IPv4 address */
    struct sockaddr_in6 *in6addr;  /* IPv6 address */
    unsigned char addrlen;         /* hardware address length */
    unsigned char hwaddr[8];       /* hardware address */
};

static rxdef rx; /* data received */
static txdef tx; /* data transmitted */

void print_help(char *prg);
void list_interfaces();
int get_local_address(char *dev, struct sockaddr *addr);
int getindex(char *ifname, struct interface *iflist);
char *get_default_interface();
char *find_active_interface(int fd, char *buffer, int len);
int get_interface_index(char *device);
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

int get_local_address(char *dev, struct sockaddr *addr)
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
    memcpy(addr, &ifr.ifr_addr, sizeof(addr));
}

void list_interfaces()
{
    struct ifaddrs *ifp;
    struct interface iflist[MAX_NUM_INTERFACES];
    int i;
    int c = 0;
    
    /* On Linux getifaddrs returns one entry per address, on Mac OS X and BSD one
       entry per interface */
    if (getifaddrs(&ifp) == -1) {
        err_sys("getifaddrs error");
    }
    memset(iflist, 0, sizeof(iflist));

    /* traverse the ifaddrs list and store the interface information in iflist */
    while (ifp) {
        if (c >= MAX_NUM_INTERFACES) {
            break;
        }
        i = getindex(ifp->ifa_name, iflist);
        if (i == -1) {
            iflist[c].name = ifp->ifa_name;
            i = c++;
        }
        switch (ifp->ifa_addr->sa_family) {
        case AF_INET:
            iflist[i].inaddr = (struct sockaddr_in *) ifp->ifa_addr;
            break;
        case AF_INET6:
            iflist[i].in6addr = (struct sockaddr_in6 *) ifp->ifa_addr;
            break;
        case AF_PACKET:
        {
            struct sockaddr_ll *ll_addr;
            
            ll_addr = (struct sockaddr_ll *) ifp->ifa_addr;
            memcpy(iflist[i].hwaddr, ll_addr->sll_addr, ll_addr->sll_halen);
            iflist[i].type = ll_addr->sll_hatype;
            iflist[i].addrlen = ll_addr->sll_halen;
            break;
        }
#ifdef MACOS
        case AF_LINK:
        {
            struct sockaddr_dl *dl_addr;
            
            dl_addr = (struct sockaddr_dl *) ifp->ifa_addr;
            memcpy(iflist[i].hwaddr, (char *) LLADDR(dl_addr), dl_addr->sdl_alen);
            iflist[i].type = dl_addr->sdl_type;
            iflist[i].addrlen = dl_addr->sdl_alen;
        }
#endif
        default:
            break;
        }
        ifp = ifp->ifa_next;
    }
    
    /* print out information for each interface */
    for (i = 0; i < c; i++) {
        printf("%s", iflist[i].name);
        switch (iflist[i].type) {
#ifdef MACOS
        case IFT_ETHER:
            printf("\tEthernet\n");
            break;
        case IFT_LOOP:
            printf("\tLoopback\n");
            break;
        case IFT_SLIP:
            printf("\tIP over generic TTY\n");
            break;
        case IFT_IEEE1394:
            printf("\tIEEE1394 High Performance SerialBus\n");
            break;
#endif
#ifdef linux
        case ARPHRD_ETHER:
            printf("\tEthernet\n");
            break;
        case ARPHRD_LOOPBACK:
            printf("\tLoopback\n");
            break;
        case ARPHRD_IEEE1394:
            printf("\tIEEE1394 High Performance SerialBus\n");
            break;
        default:
            printf("\tUnknown type: %d\n", iflist[i].type);
            break;
        }
#endif
        if (iflist[i].hwaddr) {
            if (iflist[i].addrlen == 6) {
                char hwaddr[18];
                
                snprintf(hwaddr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                         iflist[i].hwaddr[0], iflist[i].hwaddr[1],
                         iflist[i].hwaddr[2], iflist[i].hwaddr[3],
                         iflist[i].hwaddr[4], iflist[i].hwaddr[5]);
                hwaddr[17] = '\0';
                printf("\tHW addr: %s\n", hwaddr);
            } else {
                printf("\tHW addr len: %d\n", iflist[i].addrlen);
            }
        }
        if (iflist[i].inaddr) {
            char inet_addr[INET_ADDRSTRLEN];
            struct sockaddr_in *hst_addr;

            hst_addr = (struct sockaddr_in *) iflist[i].inaddr;
            inet_ntop(AF_INET, &hst_addr->sin_addr, inet_addr, INET_ADDRSTRLEN);
            printf("\tinet addr: %s\n", inet_addr);
        }
        if (iflist[i].in6addr) {
            char inet6_addr[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *hst6_addr;
            
            hst6_addr = (struct sockaddr_in6 *) iflist[i].in6addr;
            inet_ntop(AF_INET6, &hst6_addr->sin6_addr, inet6_addr, INET6_ADDRSTRLEN);
            printf("\tinet6 addr: %s\n", inet6_addr);
        }
        printf("\n");
    }
    freeifaddrs(ifp);
}

int getindex(char *ifname, struct interface *iflist)
{
    int i;

    for (i = 0; i < MAX_NUM_INTERFACES; i++) {
        if (iflist[i].name && strcmp(ifname, iflist[i].name) == 0)
            return i;
    }
    return -1;
}

/* Return the first interface which is up and running */
char *get_default_interface()
{
    struct ifconf ifc;
    int sockfd, len, lastlen;
    char *device = NULL;
    char *buffer;
    
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        err_sys("Socket error");
    }
    lastlen = 0;
    len = 10 * sizeof(struct ifreq); /* initial guess of buffer size (10 interfaces) */
    while (1) {
        if ((buffer = malloc(len)) == NULL) {
            err_sys("Unable to allocate %d bytes\n", 0);
        }
        ifc.ifc_len = len;
        ifc.ifc_buf = buffer;
        if (ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) {
            if (errno != EINVAL || lastlen != 0) {
                err_sys("ioctl error");
            }
        } else {
            device = find_active_interface(sockfd, buffer + lastlen, ifc.ifc_len);
            if (device /* active device found */ ||
                ifc.ifc_len == lastlen) { /* same value as last time */
                break;
            }
            lastlen = ifc.ifc_len;
            len += 10 * sizeof(struct ifreq);
        }
        free(buffer);
    }
    free(buffer);
    return device;
}

/* Check if the IFF_UP and IFF_RUNNING flags are set */
char *find_active_interface(int fd, char *buffer, int len)
{
    char *ptr;
    char *device;
    struct ifreq *ifr;

    for (ptr = buffer; ptr < buffer + len; ptr += sizeof(struct ifreq)) {
        ifr = (struct ifreq *) ptr;
        if (strncmp(ifr->ifr_name, "lo", 2) == 0) { /* ignore the loopback device */
            continue;
        } else {
            if (ioctl(fd, SIOCGIFFLAGS, ifr) == -1) {
                err_sys("ioctl error");
            }
            if (ifr->ifr_flags & IFF_UP &&
                ifr->ifr_flags & IFF_RUNNING) {
                int namelen = strlen(ifr->ifr_name);

                device = malloc(namelen + 1);
                strcpy(device, ifr->ifr_name);
                device[namelen] = '\0';
                return device;
            }
        }
    }
    return NULL;
}

int get_interface_index(char *dev)
{
    int sockfd;
    struct ifreq ifr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        err_sys("socket error");
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        err_sys("ioctl error");
    }
    return ifr.ifr_ifindex;
}    

/* Initialize device and prepare for reading */
int init(char **device)
{
    int sockfd;
    struct sockaddr_ll ll_addr;
    struct sigaction act, oact;

    if (!*device) {
        if (!(*device = get_default_interface())) {
            err_quit("Cannot find active network device\n");
        }
    }
    if (capture) {
        if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
            err_sys("socket error");
        }
    } else {
        if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) == -1) {
            err_sys("socket error");
        }
    }
    setuid(getuid()); /* no need for root access anymore */
    memset(&rx, 0, sizeof(rxdef));
    memset(&tx, 0, sizeof(txdef));
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

    printf("\rRX: %d  %8ld b (%d Mb)  %5.0f KB/s (%3.1f Mbit/s)",
           rx.num_packets, rx.tot_bytes, rxmbytes, rx.kbps, rxmbitspsec);
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
