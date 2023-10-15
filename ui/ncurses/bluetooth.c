#include "protocols.h"
#include "decoder/packet.h"
#include "decoder/packet_bt_hci.h"
#include "util.h"
#include "layout.h"
#include "debug.h"

void add_le_ctrl(list_view *lv, list_view_header *hdr, struct bluetooth_hci_cmd *cmd)
{
    list_view_header *sub;
    char buf[128];
    double duration;
    struct packet_flags *scanning_phy;
    int bits = 0;
    int i = 0;
    int num_bits = 0;
    int size;

    switch (GET_OCF(cmd->opcode)) {
    case BT_HCI_LE_SET_RANDOM_ADDR:
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Random Device Address: " HWSTR,
                            HW2STR(cmd->param.random_addr));
        break;
    case BT_HCI_LE_SET_EXTENDED_SCAN_PARAMS:
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Own Address Type: %s (0x%x)", get_bt_oat(cmd->param.set_scan->own_address_type),
                            cmd->param.set_scan->own_address_type);
        LV_ADD_TEXT_ELEMENT(lv, hdr, "Scanning Filter Policy: %s (0x%x)",
                            get_bt_scanning_filter_policy(cmd->param.set_scan->scanning_filter_policy),
                            cmd->param.set_scan->scanning_filter_policy);
        sub = LV_ADD_SUB_HEADER(lv, hdr, selected[UI_FLAGS], UI_FLAGS, "Scanning PHY: 0x%x",
                                cmd->param.set_scan->scanning_phy);
        scanning_phy = get_bt_scanning_phy_flags();
        size = get_bt_scanning_phy_flags_size();
        add_flags(lv, sub, cmd->param.set_scan->scanning_phy, scanning_phy, size);
        size--;
        bits = popcnt(cmd->param.set_scan->scanning_phy);
        while (i < bits && size >= 0) {
            if (strcmp(scanning_phy[size].str, "Reserved") == 0) {
                num_bits += scanning_phy[size].width;
                size--;
                continue;
            }
            if ((cmd->param.set_scan->scanning_phy >> (i + num_bits)) & 0x1) {
                sub = LV_ADD_SUB_HEADER(lv, hdr, selected[UI_FLAGS], UI_FLAGS, "%s", scanning_phy[size].str);
                LV_ADD_TEXT_ELEMENT(lv, sub, "Scan Type: %s (0x%x)", get_bt_scan_type(cmd->param.set_scan->scan_type[i]),
                                    cmd->param.set_scan->scan_type[i]);
                duration = get_bt_duration(cmd->param.set_scan->scan_interval[i]);
                if (duration > 1000)
                    snprintf(buf, 128, "%.2f sec", duration / 1000.0);
                else
                    snprintf(buf, 128, "%.2f ms", duration);
                LV_ADD_TEXT_ELEMENT(lv, sub, "Scan interval: 0x%x (%s)", cmd->param.set_scan->scan_interval[i], buf);
                duration = get_bt_duration(cmd->param.set_scan->scan_window[i]);
                if (duration > 1000)
                    snprintf(buf, 128, "%.2f sec", duration / 1000.0);
                else
                    snprintf(buf, 128, "%.2f ms", duration);
                LV_ADD_TEXT_ELEMENT(lv, sub, "Scan Window: 0x%x (%s)", cmd->param.set_scan->scan_window[i], buf);
            }
            i++;
            size--;
        }
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
