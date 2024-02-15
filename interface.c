#include <ifaddrs.h>
#include <net/if.h>
#if defined(MACOS) || defined(__FreeBSD__)
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#ifdef __linux__
#include <net/if_arp.h>
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
#include "monitor.h"
#ifdef BT_SUPPORT
#include "bluetooth.h"
#endif

#define MAX_NUM_INTERFACES 16
#define WIDTH 8

extern bool iface_eth_init(iface_handle_t *handle, unsigned char *buf, size_t len, packet_handler fn);
static bool get_active_device(iface_handle_t *handle, int fd, char *buffer, int len);
static bool get_default_device(iface_handle_t *handle);

iface_handle_t *iface_handle_create(char *dev, unsigned char *buf, size_t len,
                                    packet_handler fn)
{
    iface_handle_t *handle;

    handle = xcalloc(1, sizeof(iface_handle_t));
    if (dev)
        strncpy(handle->device, dev, IF_NAMESIZE);
    else if (!get_default_device(handle))
        return NULL;
#ifdef BT_SUPPORT
    if (iface_bt_init(handle, buf, len, fn))
        return handle;
#endif
    iface_eth_init(handle, buf, len, fn);
    return handle;
}

void iface_activate(iface_handle_t *handle, struct bpf_prog *bpf)
{
    if (!handle->active) {
        handle->op->activate(handle, bpf);
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

void iface_set_promiscuous(iface_handle_t *handle, bool enable)
{
    if (handle->op->set_promiscuous)
        handle->op->set_promiscuous(handle, enable);
}

void iface_get_mac(iface_handle_t *handle)
{
    if (handle->op->get_mac)
        handle->op->get_mac(handle);
}

void iface_get_address(iface_handle_t *handle)
{
    if (handle->op->get_address)
        handle->op->get_address(handle);
}

void list_interfaces(void)
{
    struct ifaddrs *ifp, *ifhead;
    struct interface iflist[MAX_NUM_INTERFACES] = { 0 };
    int i;
    int c = 0;

    /* On Linux getifaddrs returns one entry per address, on Mac OS X and BSD one
       entry per interface */
    if (getifaddrs(&ifp) == -1)
        err_sys("getifaddrs error");
    memset(iflist, 0, sizeof(iflist));
    ifhead = ifp;

    /* traverse the ifaddrs list and store the interface information in iflist */
    while (ifp) {
        if (c >= MAX_NUM_INTERFACES)
            break;

        /* Check if the interface is stored in iflist */
        i = -1;
        for (int j = 0; j < MAX_NUM_INTERFACES; j++) {
            if (strcmp(ifp->ifa_name, iflist[j].name) == 0) {
                i = j;
                break;
            }
        }
        /* new interface -- insert in iflist */
        if (i == -1) {
            strncpy(iflist[c].name, ifp->ifa_name, IFNAMSIZ - 1);
            i = c++;
        }

        switch (ifp->ifa_addr->sa_family) {
        case AF_INET:
            iflist[i].inaddr = (struct sockaddr_in *) ifp->ifa_addr;
            break;
        case AF_INET6:
            iflist[i].in6addr = (struct sockaddr_in6 *) ifp->ifa_addr;
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
#ifdef BT_SUPPORT
    c += bt_interfaces(iflist + c, MAX_NUM_INTERFACES - c);
#endif

    /* print out information for each interface */
    for (i = 0; i < c; i++) {
        int len = strlen(iflist[i].name);

        if (len >= WIDTH)
            printf("%-*s", len + 1, iflist[i].name);
        else
            printf("%-*s", WIDTH, iflist[i].name);

        switch (iflist[i].type) {
#if defined(MACOS) || defined(__FreeBSD__)
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
#endif
        default:
            printf("Unknown type: %d\n", iflist[i].type);
            break;
        }
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
    freeifaddrs(ifhead);
}

/* Get the first device which is up and running */
bool get_default_device(iface_handle_t *handle)
{
    struct ifconf ifc;
    int sockfd, len, lastlen;
    char *buffer;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        DEBUG("%s: Socket error", __func__);
        return false;
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
            if (get_active_device(handle, sockfd, buffer + lastlen, ifc.ifc_len) ||
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
    return true;
}

/*
 * Traverse buffer of struct ifreq and copy the name of the first device for
 * which the IFF_UP and IFF_RUNNING flags are set
 */
bool get_active_device(iface_handle_t *handle, int fd, char *buffer, int len)
{
    char *ptr;
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

                if (namelen > IF_NAMESIZE)
                    return false;
                memcpy(handle->device, ifr->ifr_name, namelen);
                handle->device[namelen] = '\0';
                return true;
            }
        }
    }
    return true;
}

void get_address(iface_handle_t *handle)
{
    struct ifreq ifr;
    int sockfd;

    strncpy(ifr.ifr_name, handle->device, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        err_sys("socket error");
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1)
        err_sys("ioctl error");
    memcpy(&handle->inaddr, &ifr.ifr_addr, sizeof(handle->inaddr));
    close(sockfd);
}
