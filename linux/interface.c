#define _GNU_SOURCE
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <linux/filter.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>
#include <sys/mman.h>
#include <linux/wireless.h>
#include "jomon.h"
#include "interface.h"

#define BUFSIZE (4 * 1024 * 1024)
#define FRAMESIZE 65536

static void linux_activate(iface_handle_t *handle, char *device, struct bpf_prog *bpf);
static void linux_close(iface_handle_t *handle);
static void linux_read_packet_mmap(iface_handle_t *handle);
static void linux_read_packet_recv(iface_handle_t *handle);
static void linux_set_promiscuous(iface_handle_t *handle, char *dev, bool enable);

struct handle_linux {
    unsigned int block_num;
    unsigned int block_size;
    unsigned int nblocks;
};

static struct iface_operations linux_op = {
    .activate = linux_activate,
    .close = linux_close,
    .read_packet = linux_read_packet_mmap,
    .set_promiscuous = linux_set_promiscuous
};

static struct iovec *iov;

/* get the interface number associated with the interface (name -> if_index mapping) */
static int get_interface_index(char *dev)
{
    int sockfd;
    struct ifreq ifr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        err_sys("socket error");
    }
    strlcpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        err_sys("ioctl error");
    }
    close(sockfd);
    return ifr.ifr_ifindex;
}

static int map_linktype(unsigned int type)
{
    switch (type) {
    case ARPHRD_ETHER:
    case ARPHRD_LOOPBACK:
        return LINKTYPE_ETHERNET;
    case ARPHRD_NONE:
        return LINKTYPE_RAW;
    default:
        return -1;
    }
}

static int get_linktype(char *dev)
{
    struct ifreq ifr;
    int sockfd;
    int ret = -1;

    strlcpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        return ret;
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
        goto done;
    ret = ifr.ifr_hwaddr.sa_family;

done:
    close(sockfd);
    return ret;
}

static bool setup_packet_mmap(iface_handle_t *handle)
{
    int val;
    unsigned int nframes;
    unsigned int frames_per_block;
    struct tpacket_req3 req;
    struct handle_linux *h;

    handle->data = xcalloc(1, sizeof(struct handle_linux));
    h = handle->data;
    req.tp_frame_size = FRAMESIZE;
    if (ctx.opt.buffer_size == 0)
        ctx.opt.buffer_size = BUFSIZE;

    /* round up to a multiple of the frame size */
    nframes = (ctx.opt.buffer_size + req.tp_frame_size - 1) / req.tp_frame_size;

    /* the block size needs to be page aligned and should be big enough to at
       least contain one frame */
    req.tp_block_size = getpagesize();
    while (req.tp_block_size < req.tp_frame_size)
        req.tp_block_size *= 2;

    frames_per_block = req.tp_block_size / req.tp_frame_size;
    req.tp_block_nr = nframes / frames_per_block;
    req.tp_frame_nr = frames_per_block * req.tp_block_nr;
    req.tp_retire_blk_tov = 60; /* timeout in ms */
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
    req.tp_sizeof_priv = 0;
    h->block_size = req.tp_block_size;
    h->nblocks = req.tp_block_nr;
    val = TPACKET_V3;
    if (setsockopt(handle->fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)) == -1)
        return false;
    val = SOF_TIMESTAMPING_RAW_HARDWARE;
    if (setsockopt(handle->fd, SOL_PACKET, PACKET_TIMESTAMP, &val, sizeof(val)) == -1)
        return false;
    if (setsockopt(handle->fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) == -1)
        return false;
    if ((handle->buf = mmap(NULL, req.tp_block_size * req.tp_block_nr, PROT_READ | PROT_WRITE,
                            MAP_SHARED, handle->fd, 0)) == MAP_FAILED)
        return false;
    iov = xmalloc(req.tp_block_nr * sizeof(*iov));
    for (unsigned int i = 0; i < req.tp_block_nr; i++) {
        iov[i].iov_base = handle->buf + (i * req.tp_block_size);
        iov[i].iov_len = req.tp_block_size;
    }
    handle->use_zerocopy = true;
    return true;
}

iface_handle_t *iface_handle_create(unsigned char *buf, size_t len, packet_handler fn)
{
    iface_handle_t *handle = xcalloc(1, sizeof(iface_handle_t));

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
    int type;

    if ((type = map_linktype(get_linktype(device))) == -1)
        err_quit("Link type not supported");
    handle->linktype = type;

    /* SOCK_RAW packet sockets include the link level header */
    if ((handle->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
        err_sys("socket error");

    /* use non-blocking socket */
    if ((flag = fcntl(handle->fd, F_GETFL, 0)) == -1)
        err_sys("fcntl error");
    if (fcntl(handle->fd, F_SETFL, flag | O_NONBLOCK) == -1)
        err_sys("fcntl error");

    if (!setup_packet_mmap(handle)) {
        DEBUG("PACKET_MMAP TPACKET_V3 is not supported");
        handle->op->read_packet = linux_read_packet_recv;
        handle->use_zerocopy = false;

        /* get timestamps */
        if (setsockopt(handle->fd, SOL_SOCKET, SO_TIMESTAMP, &n, sizeof(n)) == -1)
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
    if (bind(handle->fd, (struct sockaddr *) &ll_addr, sizeof(ll_addr)) == -1)
        err_sys("bind error");
}

void linux_close(iface_handle_t *handle)
{
    if (handle->use_zerocopy) {
        struct handle_linux *h;

        h = handle->data;
        munmap(handle->buf, h->block_size * h->nblocks);
        free(iov);
        free(handle->data);
    }
    close(handle->fd);
    handle->fd = -1;
}

void linux_read_packet_recv(iface_handle_t *handle)
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
    if (recvmmsg(handle->fd, &msg, 1, 0, NULL) == -1)
        err_sys("recvmmsg error");
    for (cmsg = CMSG_FIRSTHDR(&msg.msg_hdr); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg.msg_hdr, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
            val = (struct timeval *) CMSG_DATA(cmsg);
            break;
        }
    }
    // TODO: Should log dropped packets
    handle->on_packet(handle, handle->buf, msg.msg_len, val);
}

void linux_read_packet_mmap(iface_handle_t *handle)
{
    struct tpacket_block_desc *bd;
    struct tpacket3_hdr *hdr;
    struct timeval val;
    struct handle_linux *h;

    h = handle->data;
    bd = (struct tpacket_block_desc *) iov[h->block_num].iov_base;
    do {
        hdr = (struct tpacket3_hdr *) ((unsigned char *) bd + bd->hdr.bh1.offset_to_first_pkt);
        for (unsigned int i = 0; i < bd->hdr.bh1.num_pkts; i++) {
            val.tv_sec = hdr->tp_sec;
            val.tv_usec = hdr->tp_nsec;
            handle->on_packet(handle, (unsigned char *) hdr + hdr->tp_mac, hdr->tp_snaplen, &val);
            hdr = (struct tpacket3_hdr *) ((unsigned char *) hdr + hdr->tp_next_offset);
        }
        bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
        h->block_num = (h->block_num + 1) & (h->nblocks - 1);
        bd = (struct tpacket_block_desc *) iov[h->block_num].iov_base;
    } while ((bd->hdr.bh1.block_status & TP_STATUS_USER) == TP_STATUS_USER);
}

void linux_set_promiscuous(iface_handle_t *handle UNUSED, char *dev, bool enable)
{
    int sockfd;
    struct ifreq ifr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        err_sys("socket error");
    strlcpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1)
        err_sys("ioctl error");
    if (enable)
        ifr.ifr_flags |= IFF_PROMISC;
    else
        ifr.ifr_flags &= ~IFF_PROMISC;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr))
        err_sys("ioctl error");
    close(sockfd);
}

void get_local_mac(char *dev, unsigned char *mac)
{
    struct ifreq ifr;
    int sockfd;

    strlcpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        err_sys("socket error");
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
        err_sys("ioctl error");
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(sockfd);
}

bool is_wireless(char *dev)
{
    int sockfd;
    struct iwreq iw;
    bool ret;

    ret = false;
    memset(&iw, 0, sizeof(struct iwreq));
    strlcpy(iw.ifr_ifrn.ifrn_name, dev, IFNAMSIZ);
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        return false;
    if ((ioctl(sockfd, SIOCGIWNAME, &iw)) != -1)
        ret = true;
    close(sockfd);
    return ret;
}
