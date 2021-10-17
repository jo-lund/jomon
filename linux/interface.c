#define _GNU_SOURCE
#include <sys/socket.h>
#include <fcntl.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <linux/filter.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <linux/wireless.h>
#include "../util.h"
#include "../interface.h"
#include "../error.h"

static void linux_activate(iface_handle_t *handle, char *device, struct bpf_prog *bpf);
static void linux_close(iface_handle_t *handle);
static void linux_read_packet(iface_handle_t *handle);
static void linux_set_promiscuous(iface_handle_t *handle, char *dev, bool enable);

static struct iface_operations linux_op = {
    .activate = linux_activate,
    .close = linux_close,
    .read_packet = linux_read_packet,
    .set_promiscuous = linux_set_promiscuous
};

/* get the interface number associated with the interface (name -> if_index mapping) */
static int get_interface_index(char *dev)
{
    int sockfd;
    struct ifreq ifr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        err_sys("socket error");
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        err_sys("ioctl error");
    }
    close(sockfd);
    return ifr.ifr_ifindex;
}

iface_handle_t *iface_handle_create(unsigned char *buf, size_t len, packet_handler fn)
{
    iface_handle_t *handle = calloc(1, sizeof(iface_handle_t));

    handle->fd = -1;
    handle->op = &linux_op;
    handle->buf = buf;
    handle->len = len;
    handle->on_packet = fn;
    return handle;
}

void linux_activate(iface_handle_t *handle, char *device, struct bpf_prog *bpf)
{
    int flag;
    int n = 1;
    struct sockaddr_ll ll_addr; /* device independent physical layer address */

    /* SOCK_RAW packet sockets include the link level header */
    if ((handle->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        err_sys("socket error");
    }

    /* use non-blocking socket */
    if ((flag = fcntl(handle->fd, F_GETFL, 0)) == -1) {
        err_sys("fcntl error");
    }
    if (fcntl(handle->fd, F_SETFL, flag | O_NONBLOCK) == -1) {
        err_sys("fcntl error");
    }

    /* get timestamps */
    if (setsockopt(handle->fd, SOL_SOCKET, SO_TIMESTAMP, &n, sizeof(n)) == -1) {
        err_sys("setsockopt error");
    }

    if (bpf->size > 0) {
        struct sock_fprog code = {
            .len = bpf->size,
            .filter = (struct sock_filter *) bpf->bytecode
        };

        if (setsockopt(handle->fd, SOL_SOCKET, SO_ATTACH_FILTER, &code, sizeof(code)) == -1)
            err_sys("setsockopt error");
        bpf->size = 0; /* clear filter */
    }
    memset(&ll_addr, 0, sizeof(ll_addr));
    ll_addr.sll_family = PF_PACKET;
    ll_addr.sll_protocol = htons(ETH_P_ALL);
    ll_addr.sll_ifindex = get_interface_index(device);

    /* only receive packets on the specified interface */
    if (bind(handle->fd, (struct sockaddr *) &ll_addr, sizeof(ll_addr)) == -1) {
        err_sys("bind error");
    }
}

void linux_close(iface_handle_t *handle)
{
    close(handle->fd);
    handle->fd = -1;
}

void linux_read_packet(iface_handle_t *handle)
{
    struct mmsghdr msg;
    struct iovec iov;
    unsigned char data[64];
    struct cmsghdr *cmsg;
    struct timeval *val = NULL;

    iov.iov_base = handle->buf;
    iov.iov_len = handle->len;
    memset(&msg, 0, sizeof(struct mmsghdr));
    msg.msg_hdr.msg_iov = &iov;
    msg.msg_hdr.msg_iovlen = 1;
    msg.msg_hdr.msg_control = data;
    msg.msg_hdr.msg_controllen = 64;
    if (recvmmsg(handle->fd, &msg, 1, 0, NULL) == -1) {
        err_sys("recvmmsg error");
    }
    for (cmsg = CMSG_FIRSTHDR(&msg.msg_hdr); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg.msg_hdr, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
            val = (struct timeval *) CMSG_DATA(cmsg);
            break;
        }
    }
    // TODO: Should log dropped packets
    handle->on_packet(handle->buf, msg.msg_len, val);
}

void linux_set_promiscuous(iface_handle_t *handle UNUSED, char *dev, bool enable)
{
    int sockfd;
    struct ifreq ifr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        err_sys("socket error");
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
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

void get_local_mac(char *dev, unsigned char *mac)
{
    struct ifreq ifr;
    int sockfd;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        err_sys("socket error");
    }
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        err_sys("ioctl error");
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(sockfd);
}

bool get_iw_stats(char *dev, struct wireless *stat)
{
    int sockfd;
    struct iwreq iw;
    struct iw_statistics iw_stat;
    struct iw_range iw_range;

    strncpy(iw.ifr_ifrn.ifrn_name, dev, IFNAMSIZ - 1);
    iw.u.data.pointer = &iw_stat;
    iw.u.data.length = sizeof(struct iw_statistics);
    iw.u.data.flags = 0; // TODO: What are the possible values of flags?

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return false;
    }
    if ((ioctl(sockfd, SIOCGIWSTATS, &iw)) == -1) {
        close(sockfd);
        return false;
    }
    iw.u.data.pointer = &iw_range;
    iw.u.data.length = sizeof(struct iw_range);
    if ((ioctl(sockfd, SIOCGIWRANGE, &iw)) == -1) {
        close(sockfd);
        return false;
    }
    close(sockfd);
    stat->qual = iw_stat.qual.qual;
    stat->max_qual = iw_range.max_qual.qual;
    stat->level = iw_stat.qual.level;
    stat->noise = iw_stat.qual.noise;
    return true;
}
