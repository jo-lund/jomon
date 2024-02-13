#define _GNU_SOURCE
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bluetooth.h"
#include "monitor.h"

#define BT_IFACE "bluetooth"

static void bt_activate(iface_handle_t *handle, struct bpf_prog *bpf);
static void bt_close(iface_handle_t *handle);
static void bt_read_packet(iface_handle_t *handle);

static struct iface_operations bt_op = {
    .activate = bt_activate,
    .close = bt_close,
    .read_packet = bt_read_packet,
    .set_promiscuous = NULL
};

iface_handle_t *iface_bt_create(char *dev, unsigned char *buf, size_t len, packet_handler fn)
{
    iface_handle_t *handle;

    if (strncmp(dev, BT_IFACE, strlen(BT_IFACE)) != 0) /* not a BT device */
        return NULL;
    handle = xcalloc(1, sizeof(iface_handle_t));
    handle->device = dev;
    handle->fd = -1;
    handle->op = &bt_op;
    handle->buf = buf;
    handle->len = len;
    handle->on_packet = fn;
    return handle;
}

void bt_activate(iface_handle_t *handle, struct bpf_prog *bpf)
{
    int n = 1;
    struct sockaddr_hci addr;

    if ((handle->fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) == -1)
        err_sys("Error creating Bluetooth socket");
    if (setsockopt(handle->fd, SOL_HCI, HCI_TIME_STAMP, &n, sizeof(n)) == -1)
        err_sys("Error enabling timestamps");
    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = 0; // get device id
    if (bind(handle->fd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
        err_sys("Error binding HCI device");
}

void bt_close(iface_handle_t *handle)
{
    close(handle->fd);
    handle->fd = -1;
}

void bt_read_packet(iface_handle_t *handle)
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
        err_sys("%s recvmmsg error", __func__);
    for (cmsg = CMSG_FIRSTHDR(&msg.msg_hdr); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg.msg_hdr, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
            val = (struct timeval *) CMSG_DATA(cmsg);
            break;
        }
    }
    handle->on_packet(handle, handle->buf, msg.msg_len, val);
}

int bt_interfaces(struct interface *ifc, int cap)
{
    struct hci_dev_list_req *dl;
    struct hci_dev_info di;
    int sockfd;
    char *error = NULL;
    int ndevices = 0;

    if ((sockfd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) == -1)
        err_sys("Error creating Bluetooth socket");
    dl = xmalloc(HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(dl));
    dl->dev_num = HCI_MAX_DEV;
    if (ioctl(sockfd, HCIGETDEVLIST, dl) == -1) {
        error = "ioctl error. Cannot get device list";
        goto done;
    }
    for (uint16_t i = 0; i < dl->dev_num && i < cap; i++) {
        di.dev_id = dl->dev_req[i].dev_id;
        if (ioctl(sockfd, HCIGETDEVINFO, &di) == -1) {
            error = "ioctl error. Cannot get device info";
            goto done;
        }
        snprintf(ifc[i].name, IF_NAMESIZE, BT_IFACE"%u", i);
        memcpy(ifc[i].hwaddr, di.bdaddr.b, 6);
        ifc[i].type = di.type;
        ifc[i].addrlen = 6;
        ndevices++;
    }

done:
    free(dl);
    close(sockfd);
    if (error)
        err_sys(error);
    return ndevices;
}
