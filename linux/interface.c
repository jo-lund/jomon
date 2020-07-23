#define _GNU_SOURCE
#include "../interface.h"
#include "../error.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <linux/filter.h>
#include "../util.h"

static void linux_activate(iface_handle_t *handle, char *device, struct bpf_prog bpf);
static void linux_close(iface_handle_t *handle);
static void linux_read_packet(iface_handle_t *handle);

static struct iface_operations linux_op = {
    .activate = linux_activate,
    .close = linux_close,
    .read_packet = linux_read_packet
};

iface_handle_t *iface_handle_create()
{
    iface_handle_t *handle = calloc(1, sizeof(iface_handle_t));

    handle->sockfd = -1;
    handle->op = &linux_op;
    return handle;
}

void linux_activate(iface_handle_t *handle, char *device, struct bpf_prog bpf)
{
    int flag;
    int n = 1;
    struct sockaddr_ll ll_addr; /* device independent physical layer address */

    /* SOCK_RAW packet sockets include the link level header */
    if ((handle->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        err_sys("socket error");
    }

    /* use non-blocking socket */
    if ((flag = fcntl(handle->sockfd, F_GETFL, 0)) == -1) {
        err_sys("fcntl error");
    }
    if (fcntl(handle->sockfd, F_SETFL, flag | O_NONBLOCK) == -1) {
        err_sys("fcntl error");
    }

    /* get timestamps */
    if (setsockopt(handle->sockfd, SOL_SOCKET, SO_TIMESTAMP, &n, sizeof(n)) == -1) {
        err_sys("setsockopt error");
    }

    if (bpf.size > 0) {
        struct sock_fprog code = {
            .len = bpf.size,
            .filter = (struct sock_filter *) bpf.bytecode
        };

        if (setsockopt(handle->sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &code, sizeof(code)) == -1)
            err_sys("setsockopt error");
    }
    memset(&ll_addr, 0, sizeof(ll_addr));
    ll_addr.sll_family = PF_PACKET;
    ll_addr.sll_protocol = htons(ETH_P_ALL);
    ll_addr.sll_ifindex = get_interface_index(device);

    /* only receive packets on the specified interface */
    if (bind(handle->sockfd, (struct sockaddr *) &ll_addr, sizeof(ll_addr)) == -1) {
        err_sys("bind error");
    }
}

void linux_close(iface_handle_t *handle)
{
    close(handle->sockfd);
    handle->sockfd = -1;
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

    if (recvmmsg(handle->sockfd, &msg, 1, 0, NULL) == -1) {
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
