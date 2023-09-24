#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include "bluetooth.h"

#define BT_IFACE "bluetooth"

int bt_interfaces(struct interface *ifc, int cap)
{
    struct hci_dev_list_req *dl;
    struct hci_dev_info di;
    int sockfd;
    char *error = NULL;
    int ndevices = 0;

    if ((sockfd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) == -1)
        err_sys("Error opening Bluetooth socket");
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
        snprintf(ifc[i].name, IFNAMSIZ, BT_IFACE"%u", i);
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
