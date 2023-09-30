#include <stdio.h>
#include "print_protocol.h"
#include "decoder/packet.h"
#include "decoder/packet_bt_hci.h"

void print_bt(char *buf, int n, void *data)
{
    struct protocol_info *pinfo;
    struct packet_data *pdata = data;
    struct bluetooth_hci_info *bt = pdata->data;

    pinfo = get_protocol(pdata->id);
    switch (bt->type) {
    case BT_HCI_COMMAND:
        PRINT_ADDRESS(buf, n, "host", "controller");
        break;
    case BT_HCI_EVENT:
        PRINT_ADDRESS(buf, n, "controller", "host");
        break;
    default:
        break;
    }
    PRINT_PROTOCOL(buf, n, pinfo->short_name);
    bt2string(buf, n, bt);
}
