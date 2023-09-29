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
    PRINT_INFO(buf, n, "Event   ");
    switch (event->code) {
    case BT_HCI_INQUIRY_COMPLETE:
        PRINT_INFO(buf, n, "HCI Inquiry Complete");
        break;
    case BT_HCI_CMD_COMPLETE:
        PRINT_INFO(buf, n, "HCI Command Complete: Command opcode: 0x%x",
                   event->param.cmd->opcode);

        break;
    case BT_HCI_CMD_STATUS:
        PRINT_INFO(buf, n, "HCI Command Status: %u  Command opcode: 0x%x",
                   event->param.cstat->status, event->param.cstat->opcode);
        break;
    case BT_HCI_EXT_INQ_RESULT:
        PRINT_INFO(buf, n, "HCI Extended Inquiry Result");
        break;
    case BT_HCI_LE_META:
        switch (event->param.meta.subevent_code) {
        case BT_HCI_LE_CONN_COMPLETE:
            PRINT_INFO(buf, n, "LE Meta: LE Connection Complete");
            break;
        case BT_HCI_LE_ADV_REPORT:
            PRINT_INFO(buf, n, "LE Meta: LE Advertising Report");
            break;
        case BT_HCI_LE_CONN_UPDATE:
            PRINT_INFO(buf, n, "LE Meta: LE Connection Update Complete");
            break;
        case BT_HCI_LE_READ_REMOTE_COMPLETE:
            PRINT_INFO(buf, n, "LE Meta: LE Read Remote Features Complete");
            break;
        case BT_HCI_LE_LONG_TERM_KEY_REQ:
            PRINT_INFO(buf, n, "LE Meta: LE Long Term Key Request");
            break;
        case BT_HCI_LE_REMOTE_CONN_PARAM_REQ:
            PRINT_INFO(buf, n, "LE Meta: LE Remote Connection Parameter Request");
            break;
        case BT_HCI_LE_DATA_LEN_CHANGE:
            PRINT_INFO(buf, n, "LE Meta: LE Data Length Change");
            break;
        case BT_HCI_LE_READ_LOC_PUB_KEY_COMPLETE:
            PRINT_INFO(buf, n, "LE Meta: LE Read Local P-256 Public Key Complete");
            break;
        case BT_HCI_LE_GEN_DHKEY_COMPLETE:
            PRINT_INFO(buf, n, "LE Meta: LE Generate DHKey Complete");
            break;
        case BT_HCI_LE_ENHANCED_CONN_COMPLETE:
            PRINT_INFO(buf, n, "LE Meta: LE Enhanced Connection Complete");
            break;
        case BT_HCI_LE_DIRECT_ADV_REPORT:
            PRINT_INFO(buf, n, "LE Meta: LE Direct Advertising Report");
            break;
        case BT_HCI_LE_PHY_UPDATE_COMPLETE:
            PRINT_INFO(buf, n, "LE Meta: LE PHY Update Complete");
            break;
        case BT_HCI_LE_EXT_ADV_REPORT:
            PRINT_INFO(buf, n, "LE Meta: LE Extended Advertising Report");
            break;
        default:
            break;
        }
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
