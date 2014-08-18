/* Network traffic monitor
 *
 * This program will monitor all incoming/outgoing network traffic and 
 * print out the speed of the download/upload. It uses the libpcap library 
 * to capture packets (http://www.tcpdump.org). On Mac OS X this library 
 * will use the BSD packet filter (BPF) to interface with the network device.
 *
 * The speed of the download/upload is based on the network throughput, which
 * means that the bit rate will be measured at a reference point above the 
 * datalink layer, i.e., the reference point will be the IP layer.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/if_types.h>
#include <sys/ioctl.h>
#include "misc.h"
#include "pcap_handler.h"

void print_help(char *prg);
void err_quit(char *error);
void list_interfaces();
int get_local_address(char *dev, struct sockaddr *addr);

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

    // need proper closing of resources. Make a signal.
    init_pcap(device);
    //pcap_close(pcap_handle);
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
    struct ifaddrs *ifp_t;
    char *ifname;
    char pifname[256];

    // getifaddrs -- get interface addresses (only available on Mac OS X and BSD)
    if (getifaddrs(&ifp) == -1) {
        perror("getifaddrs error");
        exit(1);
    }

    ifp_t = ifp;
    while (ifp_t) {
        ifname = ifp_t->ifa_name;
        if (strcmp(ifname, pifname)) // don't print the same interface name
            printf("%s: ", ifname);
        
        switch (ifp_t->ifa_addr->sa_family) {
        case AF_INET:
        {
            struct sockaddr_in *hst_addr;
            char str[INET_ADDRSTRLEN];

            hst_addr = (struct sockaddr_in *) ifp_t->ifa_addr;
            inet_ntop(AF_INET, &hst_addr->sin_addr, str, INET_ADDRSTRLEN);
            printf("\tinet %s\n", str);
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 *hst_addr;
            char str[INET6_ADDRSTRLEN];

            hst_addr = (struct sockaddr_in6 *) ifp_t->ifa_addr;
            inet_ntop(AF_INET6, &hst_addr->sin6_addr, str, INET6_ADDRSTRLEN);
            printf("\tinet6 %s\n", str);
            break;
        }
        case AF_LINK:
        {
            struct sockaddr_dl *dl_addr;
            
            dl_addr = (struct sockaddr_dl *) ifp_t->ifa_addr;
            // Link address is always NULL
            // LLADDR returns a pointer to the link level address
            //printf("\tether %s\n", LLADDR(dl_addr));

            switch (dl_addr->sdl_type) {
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
            default:
                printf("\n");
            }
        }
        default:
            break;
        }
        strncpy(pifname, ifname, sizeof(pifname));
        ifp_t = ifp_t->ifa_next;        
    }
    
    freeifaddrs(ifp);
}
