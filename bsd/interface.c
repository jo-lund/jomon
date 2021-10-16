#include <ifaddrs.h>
#include <string.h>
#include <sys/types.h>
#include <net/if_dl.h>
#include "../interface.h"
#include "../attributes.h"
#include "../error.h"

static void bsd_activate(iface_handle_t *handle, char *device, struct bpf_prog *bpf);
static void bsd_close(iface_handle_t *handle);
static void bsd_read_packet(iface_handle_t *handle);

static struct iface_operations bsd_op = {
    .activate = bsd_activate,
    .close = bsd_close,
    .read_packet = bsd_read_packet,
};

iface_handle_t *iface_handle_create(unsigned char *buf, size_t len, packet_handler fn)
{
    iface_handle_t *handle = calloc(1, sizeof(iface_handle_t));

    handle->sockfd = -1;
    handle->op = &bsd_op;
    handle->buf = buf;
    handle->len = len;
    handle->on_packet = fn;
    return handle;
}

void bsd_activate(iface_handle_t *handle UNUSED, char *device UNUSED, struct bpf_prog *bpf UNUSED)
{

}

void bsd_close(iface_handle_t *handle UNUSED)
{

}

void bsd_read_packet(iface_handle_t *handle UNUSED)
{

}

void get_local_mac(char *dev UNUSED, unsigned char *mac)
{
     struct ifaddrs *ifp, *ifhead;

    if (getifaddrs(&ifp) == -1)
        err_sys("getifaddrs error");
    ifhead = ifp;
    while (ifp) {
        if (ifp->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *dl_addr;

            dl_addr = (struct sockaddr_dl *) ifp->ifa_addr;
            memcpy(mac, (char *) LLADDR(dl_addr), dl_addr->sdl_alen);
            break;
        }
    }
    freeifaddrs(ifhead);
}

bool get_iw_stats(char *dev UNUSED, struct wireless *stat UNUSED)
{
    return false;
}
