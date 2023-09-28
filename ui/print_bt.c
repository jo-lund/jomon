#include <stdio.h>
#include "print_protocol.h"
#include "decoder/packet.h"
#include "decoder/packet_bt_hci.h"

static void print_bt_hci_cmd(char *buf, int n, struct bluetooth_hci_cmd *cmd)
{
    PRINT_INFO(buf, n, "Command ");
    switch (cmd->opcode.ogf) {
    case BT_LINK_CTRL_CMD:
        switch (cmd->opcode.ocf) {
        case BT_HCI_INQUIRY:
            PRINT_INFO(buf, n, "Inquiry: LAP: " LAPSTR "  Inquiry length: %u  Number of Responses: %u",
                       LAP2STR(cmd->param.inq->lap), cmd->param.inq->inquiry_len, cmd->param.inq->nresp);
            break;
        case BT_HCI_INQUIRY_CANCEL:
            PRINT_INFO(buf, n, "Inquiry Cancel");
            break;
        default:
            break;
        }
        break;
    case BT_LE_CTRL_CMD:
        switch (cmd->opcode.ocf) {
        case BT_HCI_LE_SET_RANDOM_ADDR:
            PRINT_INFO(buf, n, "LE Set Random Address: " HWSTR,
                       HW2STR(cmd->param.random_addr));
            break;
        case BT_HCI_LE_SET_EXTENDED_SCAN_PARAMS:
            PRINT_INFO(buf, n, "LE Set Extended Scan Parameters");
            break;
        case BT_HCI_LE_SET_EXTENDED_SCAN_ENABLE:
            PRINT_INFO(buf, n, "LE Set Extended Scan Enable");
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
}

static void print_bt_hci_event(char *buf, int n, struct bluetooth_hci_event *event)
{
    PRINT_INFO(buf, n, "Event ");
    switch (event->code) {
    case BT_HCI_INQUIRY_COMPLETE:
        PRINT_INFO(buf, n, "HCI Inquiry Complete");
        break;
    case BT_HCI_CMD_COMPLETE:
        PRINT_INFO(buf, n, "HCI Command Complete: Number of HCI packets: %u  Command opcode: 0x%x",
                   event->param.cmd->ncmdpkt, event->param.cmd->opcode);
        break;
    default:
        break;
    }
}

void print_bt(char *buf, int n, void *data)
{
    struct protocol_info *pinfo;
    struct packet_data *pdata = data;
    struct bluetooth_hci_info *bt = pdata->data;

    pinfo = get_protocol(pdata->id);
    switch (bt->type) {
    case BT_HCI_COMMAND:
        PRINT_ADDRESS(buf, n, "host", "controller");
        PRINT_PROTOCOL(buf, n, pinfo->short_name);
        print_bt_hci_cmd(buf, n, bt->cmd);
        break;
    case BT_HCI_EVENT:
        PRINT_ADDRESS(buf, n, "controller", "host");
        PRINT_PROTOCOL(buf, n, pinfo->short_name);
        print_bt_hci_event(buf, n, bt->event);
        break;
    default:
        break;
    }
}
