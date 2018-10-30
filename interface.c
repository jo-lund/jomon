#include <ifaddrs.h>
#ifdef MACOS
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#ifdef __linux__
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <linux/wireless.h>
#endif
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "interface.h"
#include "error.h"

#define MAX_NUM_INTERFACES 16

struct interface {
    char *name;                    /* interface name */
    unsigned short type;           /* interface type, e.g. Ethernet, Firewire etc. */
    struct sockaddr_in *inaddr;    /* IPv4 address */
    struct sockaddr_in6 *in6addr;  /* IPv6 address */
    unsigned char addrlen;         /* hardware address length */
    unsigned char hwaddr[8];       /* hardware address */
};

static char *get_active_interface(int fd, char *buffer, int len);

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
        /* Check if the interface is stored in iflist */
        i = -1;
        for (int j = 0; j < MAX_NUM_INTERFACES; j++) {
            if (iflist[j].name && strcmp(ifp->ifa_name, iflist[j].name) == 0) {
                i = j;
                break;
            }
        }
        /* new interface -- insert in iflist */
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
        int len = strlen(iflist[i].name);
        int width = 8;

        if (len >= 8) {
            width = len + 1;
            printf("%-*s", width, iflist[i].name);
        } else {
            printf("%-*s", width, iflist[i].name);
        }
        switch (iflist[i].type) {
#ifdef MACOS
        case IFT_ETHER:
            printf("Ethernet\n");
            break;
        case IFT_LOOP:
            printf("Loopback\n");
            break;
        case IFT_SLIP:
            printf("IP over generic TTY\n");
            break;
        case IFT_IEEE1394:
            printf("IEEE1394 High Performance SerialBus\n");
            break;
#endif
#ifdef __linux__
        case ARPHRD_ETHER:
            printf("Ethernet\n");
            break;
        case ARPHRD_LOOPBACK:
            printf("Loopback\n");
            break;
        case ARPHRD_IEEE1394:
            printf("IEEE1394 High Performance SerialBus\n");
            break;
        default:
            printf("Unknown type: %d\n", iflist[i].type);
            break;
#endif
        }
        if (iflist[i].hwaddr) {
            if (iflist[i].addrlen == 6) {
                char hwaddr[18];

                snprintf(hwaddr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                         iflist[i].hwaddr[0], iflist[i].hwaddr[1],
                         iflist[i].hwaddr[2], iflist[i].hwaddr[3],
                         iflist[i].hwaddr[4], iflist[i].hwaddr[5]);
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

        /* SIOCGIFCONF takes a struct ifconf *. The ifc_buf field points to a
         * buffer of length ifc_len bytes, into which the kernel writes a list
         * of type struct ifreq [] */
        if (ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) {
            if (errno != EINVAL || lastlen != 0) {
                err_sys("ioctl error");
            }
        } else {
            device = get_active_interface(sockfd, buffer + lastlen, ifc.ifc_len);
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
    close(sockfd);
    return device;
}

/*
 * Traverse buffer of struct ifreq and return the name of the first device for
 * which the IFF_UP and IFF_RUNNING flags are set
 */
char *get_active_interface(int fd, char *buffer, int len)
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
            if (ifr->ifr_flags & IFF_UP && ifr->ifr_flags & IFF_RUNNING) {
                size_t namelen = strlen(ifr->ifr_name);

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
    close(sockfd);
    return ifr.ifr_ifindex;
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
    close(sockfd);
}

bool get_iw_stats(char *dev, struct iw_statistics *iwstat)
{
    int sockfd;
    struct iwreq iw;

    strncpy(iw.ifr_ifrn.ifrn_name, dev, IFNAMSIZ);
    iw.u.data.pointer = iwstat;
    iw.u.data.length = sizeof(struct iw_statistics);
    iw.u.data.flags = 0; // TODO: What are the possible values of flags?

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return false;
    }
    if ((ioctl(sockfd, SIOCGIWSTATS, &iw)) == -1) {
        close(sockfd);
        return false;
    }
    close(sockfd);
    return true;
}

bool get_iw_range(char *dev, struct iw_range *iwrange)
{
    int sockfd;
    struct iwreq iw;

    strncpy(iw.ifr_ifrn.ifrn_name, dev, IFNAMSIZ);
    iw.u.data.pointer = iwrange;
    iw.u.data.length = sizeof(struct iw_range);
    iw.u.data.flags = 0;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return false;
    }
    if ((ioctl(sockfd, SIOCGIWRANGE, &iw)) == -1) {
        close(sockfd);
        return false;
    }
    close(sockfd);
    return true;
}

void set_promiscuous(char *dev, bool enable)
{
    int sockfd;
    struct ifreq ifr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        err_sys("socket error");
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
        err_sys("ioctl error");
    }
    if (enable) {
        ifr.ifr_flags |= IFF_PROMISC;
    } else {
        ifr.ifr_flags &= ~IFF_PROMISC;
    }
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr)) {
        err_sys("ioctl error");
    }
}
