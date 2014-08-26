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
#if 0
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
#include "misc.h"
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

void print_help(char *prg);
void err_quit(char *error);
void list_interfaces();
int get_local_address(char *dev, struct sockaddr *addr);
int getindex(char *ifname, struct interface *iflist);

int main(int argc, char **argv)
{
    char *device = NULL;
    char *prg_name = argv[0];
    int opt;

    promiscuous = 0;
    while ((opt = getopt(argc, argv, "i:lhvp")) != -1) {
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
}

void err_quit(char *error)
{
    printf("Error: %s\n", error);
    exit(1);
}

void print_help(char *prg)
{
    printf("Usage: %s [-lvhp] [-i interface]\n", prg);
    printf("Options:\n");
    printf("     -i  Specify network interface\n");
    printf("     -l  List available interfaces\n");
    printf("     -p  Use promiscuous mode\n");
    printf("     -v  Print verbose information\n"); 
    printf("     -h  Print this help summary\n");
}

int check_ip(const u_char *bytes)
{
    struct ip *ip;

    ip = (struct ip *) bytes;
 
    if (ip->ip_v != IPVERSION) {
        if (verbose)
            printf("ip->ip_v != IPVERSION: %d\n", ip->ip_v);
        bad_packets++;
        return -1;
    }
    return 0;
}

int get_local_address(char *dev, struct sockaddr *addr)
{
    struct ifreq ifr;
    int sockfd;

    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
    ifr.ifr_addr.sa_family = AF_INET;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket error");
        return -1;
    }
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl error");
        return -1;
    }

    memcpy(addr, &ifr.ifr_addr, sizeof(addr));
    return 0;
}

void list_interfaces()
{
    struct ifaddrs *ifp;
    struct interface iflist[MAX_NUM_INTERFACES];
    int i;
    int c = 0;
    
    /* On Linux getifaddrs returns one entry per address, on Mac OS X and BSD one entry
       per interface */
    if (getifaddrs(&ifp) == -1) {
        perror("getifaddrs error");
        exit(1);
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
#if 0
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
#if 0
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
            if (iflist[i].addrlen = 6) {
                char hwaddr[18];
                
                snprintf(hwaddr, 18, "%02x:%02x:%02x:%02x:%02x:%02x", iflist[i].hwaddr[0],
                         iflist[i].hwaddr[1], iflist[i].hwaddr[2], iflist[i].hwaddr[3],
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
