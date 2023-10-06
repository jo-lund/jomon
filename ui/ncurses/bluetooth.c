#include "protocols.h"
#include "decoder/packet.h"
#include "decoder/packet_bt_hci.h"
#include "util.h"
#include "layout.h"

void add_le_ctrl(list_view *lv, list_view_header *hdr, struct bluetooth_hci_cmd *cmd)
{
    switch (GET_OCF(cmd->opcode)) {
    case BT_HCI_LE_SET_RANDOM_ADDR:
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Random Device Address: " HWSTR,
                            HW2STR(cmd->param.random_addr));
        break;
    case BT_HCI_LE_SET_EXTENDED_SCAN_PARAMS:
        break;
    case BT_HCI_LE_SET_EXTENDED_SCAN_ENABLE:
        break;
    default:
        break;
    }
}

void add_event(list_view *lv, list_view_header *hdr, struct bluetooth_hci_event *event)
{
    switch (event->code) {
    case BT_HCI_CMD_COMPLETE:
        if (!event->param.cmd)
            return;
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Number of HCI command packets: %d", event->param.cmd->ncmdpkt);
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Command opcode: %s (0x%x)", get_bt_command(event->param.cmd->opcode),
                            event->param.cmd->opcode);
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Status: %s (0x%x)", get_bt_error_string(event->param.cmd->return_param),
                            event->param.cmd->return_param);
        break;
    default:
        break;
    }
}

void add_bt_information(void *w, void *sw, void *data)
{
    list_view *lv = w;
    list_view_header *hdr = sw;
    list_view_header *sub;
    struct bluetooth_hci_info *bt = ((struct packet_data *) data)->data;

    LV_ADD_TEXT_ELEMENT(lv, hdr, "Type: %s (%u)", get_bt_type(bt->type), bt->type);
    switch (bt->type) {
    case BT_HCI_COMMAND:
        if (!bt->cmd)
            return;
        sub = LV_ADD_SUB_HEADER(lv, hdr, selected[UI_FLAGS], UI_FLAGS, "Opcode: %s (0x%x)",
                                get_bt_command(bt->cmd->opcode), bt->cmd->opcode);
        add_flags(lv, sub, bt->cmd->opcode, get_bt_opcode_flags(),
                  get_bt_opcode_flags_size());
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Parameter Total Length: %u", bt->cmd->param_len);
        switch (GET_OGF(bt->cmd->opcode)) {
        case BT_LINK_CTRL_CMD:
            break;
        case BT_CTRL_BB_CMD:
            break;
        case BT_INF_PARAMS:
            break;
        case BT_LE_CTRL_CMD:
            add_le_ctrl(lv, hdr, bt->cmd);
            break;
        default:
            break;
        }
        break;
    case BT_HCI_EVENT:
        if (!bt->event)
            return;
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Event Code: %s (0x%x)", get_bt_event_code(bt->event->code),
                            bt->event->code);
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Parameter Total Length: %u", bt->event->param_len);
        add_event(lv, hdr, bt->event);
        break;
    default:
        break;
    }
}
