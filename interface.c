#include <ifaddrs.h>
#include <net/if.h>
#if defined(MACOS) || defined(__FreeBSD__)
#include <net/if_dl.h>
#endif
#ifdef __linux__
#include <netpacket/packet.h>
#endif
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <net/ethernet.h>
#include "interface.h"
#include "jomon.h"

#define MAX_NUM_INTERFACES 16

static char *get_active_interface(int fd, char *buffer, int len);
char *get_linktype_description(int type, char *name);

struct interface {
    char *name;                /* interface name */
    unsigned short type;       /* interface type, e.g. Ethernet, Firewire etc. */
    list_t *inaddr;            /* IPv4 addresses */
    list_t *in6addr;           /* IPv6 addresses */
    unsigned char addrlen;     /* hardware address length */
    unsigned char hwaddr[8];   /* hardware address */
};

void iface_activate(iface_handle_t *handle, char *device, struct bpf_prog *bpf)
{
    if (!handle->active) {
        handle->op->activate(handle, device, bpf);
        handle->active = true;
    }
}

void iface_close(iface_handle_t *handle)
{
    if (handle->active) {
        handle->op->close(handle);
        handle->active = false;
    }
}

void iface_read_packet(iface_handle_t *handle)
{
    handle->op->read_packet(handle);
}

void iface_set_promiscuous(iface_handle_t *handle, char *dev, bool enable)
{
    handle->op->set_promiscuous(handle, dev, enable);
}

void list_interfaces(void)
{
    struct ifaddrs *ifp, *ifhead;
    struct interface iflist[MAX_NUM_INTERFACES];
    int i;
    int c = 0;

    /* On Linux getifaddrs returns one entry per address, on Mac OS X and BSD one
       entry per interface */
    if (getifaddrs(&ifp) == -1) {
        err_sys("getifaddrs error");
    }
    memset(iflist, 0, sizeof(iflist));
    ifhead = ifp;

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
            iflist[c].inaddr = list_init(NULL);
            iflist[c].in6addr = list_init(NULL);
            i = c++;
        }

        if (!ifp->ifa_addr) {
            ifp = ifp->ifa_next;
            continue;
        }
        switch (ifp->ifa_addr->sa_family) {
        case AF_INET:
            list_push_back(iflist[i].inaddr, ifp->ifa_addr);
            break;
        case AF_INET6:
            list_push_back(iflist[i].in6addr, ifp->ifa_addr);
            break;
#ifdef __linux__
        case AF_PACKET:
        {
            struct sockaddr_ll *ll_addr;

            ll_addr = (struct sockaddr_ll *) ifp->ifa_addr;
            memcpy(iflist[i].hwaddr, ll_addr->sll_addr, ll_addr->sll_halen);
            iflist[i].type = ll_addr->sll_hatype;
            iflist[i].addrlen = ll_addr->sll_halen;
            break;
        }
#endif
#if defined(MACOS) || defined(__FreeBSD__)
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
        printf("%s\n", get_linktype_description(iflist[i].type, iflist[i].name));
        if (iflist[i].addrlen == 6) {
            char hwaddr[18];

            snprintf(hwaddr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                     iflist[i].hwaddr[0], iflist[i].hwaddr[1],
                     iflist[i].hwaddr[2], iflist[i].hwaddr[3],
                     iflist[i].hwaddr[4], iflist[i].hwaddr[5]);
            printf("\tHW addr: %s\n", hwaddr);
        } else {
            DEBUG("HW addr len: %d\n", iflist[i].addrlen);
        }
        if (list_size(iflist[i].inaddr) > 0) {
            char inet_addr[INET_ADDRSTRLEN];
            struct sockaddr_in *hst_addr;
            const node_t *n;

            DLIST_FOREACH(iflist[i].inaddr, n) {
                hst_addr = (struct sockaddr_in *) list_data(n);
                inet_ntop(AF_INET, &hst_addr->sin_addr, inet_addr, INET_ADDRSTRLEN);
                printf("\tinet addr: %s\n", inet_addr);
            }
        }
        if (list_size(iflist[i].in6addr) > 0) {
            char inet6_addr[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *hst6_addr;
            const node_t *n;

            DLIST_FOREACH(iflist[i].in6addr, n) {
                hst6_addr = (struct sockaddr_in6 *) list_data(n);
                inet_ntop(AF_INET6, &hst6_addr->sin6_addr, inet6_addr, INET6_ADDRSTRLEN);
                printf("\tinet6 addr: %s\n", inet6_addr);
            }

        }
        printf("\n");
    }
    freeifaddrs(ifhead);
    for (i = 0; i < c; i++) {
        if (iflist[i].inaddr)
            list_free(iflist[i].inaddr, NULL);
        if (iflist[i].in6addr)
            list_free(iflist[i].in6addr, NULL);
    }
}

char *get_default_interface(void)
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
        buffer = xmalloc(len);
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

                device = xmalloc(namelen + 1);
                memcpy(device, ifr->ifr_name, namelen);
                device[namelen] = '\0';
                return device;
            }
        }
    }
    return NULL;
}

void get_local_address(char *dev, struct sockaddr *addr)
{
    struct ifreq ifr;
    int sockfd;

    strlcpy(ifr.ifr_name, dev, IFNAMSIZ);
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

bool linktype_supported(const uint32_t linktype)
{
    switch (linktype) {
    case LINKTYPE_NULL:
    case LINKTYPE_ETHERNET:
    case LINKTYPE_IEEE802:
    case LINKTYPE_RAW:
        return true;
    default:
        return false;
    }
}
