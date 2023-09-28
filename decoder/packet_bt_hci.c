#include "packet_bt_hci.h"
#include "packet.h"
#include "util.h"

#define HCI_CMD_HDR 3
#define HCI_EVENT_HDR 2
#define BT_WITH_PHDR 5

#define READ_BDADDR(d, s)   \
    do {                    \
        (d)[0] = (s)[5];    \
        (d)[1] = (s)[4];    \
        (d)[2] = (s)[3];    \
        (d)[3] = (s)[2];    \
        (d)[4] = (s)[1];    \
        (d)[5] = (s)[0];    \
    } while (0);

extern void add_bt_information(void *w, void *sw, void *data);
extern void print_bt(char *buf, int n, void *data);
static packet_error handle_bt(struct protocol_info *pinfo, unsigned char *buf,
                              int n, struct packet_data *pdata);

static struct protocol_info bt = {
    .short_name = "BT HCI",
    .long_name = "Bluetooth HCI",
    .decode = handle_bt,
    .print_pdu = print_bt,
    .add_pdu = add_bt_information
};

static struct packet_flags scanning_phy[] = {
    { "Scan advertisements on the LE 1M PHY", 1, NULL },
    { "Reserved", 1, NULL },
    { "Scan advertisements on the LE Coded PHY", 1, NULL },
    { "Reserved", 5, NULL }
};

static inline int popcnt(uint32_t x)
{
#ifdef __builtin_popcount
    return __builtin_popcount(x);
#else
    int c = 0;

    while (x) {
        x &= x - 1;
        c++;
    }
    return c;
#endif
}

void register_bt_hci(void)
{
    register_protocol(&bt, DATALINK, LINKTYPE_BT_HCI_H4);
    register_protocol(&bt, DATALINK, LINKTYPE_BT_HCI_H4_WITH_PHDR);
}

static packet_error parse_le_ctrl(unsigned char *buf, int n, struct bluetooth_hci_cmd *cmd)
{
    int bits;

    switch (cmd->opcode.ocf) {
    case BT_HCI_LE_SET_RANDOM_ADDR:
        if (n != 6)
            return DECODE_ERR;
        READ_BDADDR(cmd->param.random_addr, buf);
        break;
    case BT_HCI_LE_SET_EXTENDED_SCAN_PARAMS:
        if (n < 3)
            return DECODE_ERR;
        cmd->param.set_scan = mempool_alloc(sizeof(*cmd->param.set_scan));
        cmd->param.set_scan->own_address_type = *buf++;
        cmd->param.set_scan->scanning_filter_policy = *buf++;
        cmd->param.set_scan->scanning_phy.le_1m = buf[0] >> 7;
        cmd->param.set_scan->scanning_phy.le_coded = (buf[0] >> 5) & 0x1;
        bits = popcnt(buf[0]);
        buf++;
        n -= 3;
        if (bits == 0 || bits > 2 || n < bits)
            return DECODE_ERR;
        cmd->param.set_scan->scan_type = mempool_alloc(bits);
        for (int i = 0; i < bits; i++)
            cmd->param.set_scan->scan_type[i] = *buf++;
        n -= bits;
        if (n < 2 * bits)
            return DECODE_ERR;
        cmd->param.set_scan->scan_interval = mempool_alloc(bits);
        for (int i = 0; i < bits; i++)
            cmd->param.set_scan->scan_interval[i] = read_uint16le(&buf);
        n = n - 2 * bits;
        if (n < 2 * bits)
            return DECODE_ERR;
        cmd->param.set_scan->scan_window = mempool_alloc(bits);
        for (int i = 0; i < bits; i++)
            cmd->param.set_scan->scan_window[i] = read_uint16le(&buf);
        n = n - 2 * bits;
        break;
    case BT_HCI_LE_SET_EXTENDED_SCAN_ENABLE:
        if (n < 6)
            return DECODE_ERR;
        cmd->param.scan_enable = mempool_alloc(sizeof(*cmd->param.scan_enable));
        cmd->param.scan_enable->enable = *buf++;
        cmd->param.scan_enable->filter_dup = *buf++;
        cmd->param.scan_enable->duration = read_uint16le(&buf);
        cmd->param.scan_enable->period = read_uint16le(&buf);
        break;
    default:
        break;
    }
    return NO_ERR;
}

static packet_error parse_link_ctrl(unsigned char *buf, int n, struct bluetooth_hci_cmd *cmd)
{
    switch (cmd->opcode.ocf) {
    case BT_HCI_INQUIRY:
        if (n < 5)
            return DECODE_ERR;
        cmd->param.inq = mempool_alloc(sizeof(*cmd->param.inq));
        cmd->param.inq->lap[0] = buf[2];
        cmd->param.inq->lap[1] = buf[1];
        cmd->param.inq->lap[2] = buf[0];
        buf += 3;
        cmd->param.inq->inquiry_len = *buf++;
        cmd->param.inq->nresp = *buf++;
        break;
    case BT_HCI_INQUIRY_CANCEL:
    default:
        break;
    }
    return NO_ERR;
}

static packet_error parse_cmd(unsigned char *buf, int n, struct bluetooth_hci_info *bt)
{
    struct bluetooth_hci_cmd *cmd;
    uint16_t opcode;

    if (n < HCI_CMD_HDR)
        return DECODE_ERR;
    cmd = mempool_alloc(sizeof(*cmd));
    bt->cmd = cmd;
    opcode = read_uint16le(&buf);
    n -= 2;
    cmd->opcode.ocf = opcode & 0x03ff;
    cmd->opcode.ogf = (opcode & 0xfc00) >> 10;
    cmd->param_len = *buf++;
    n--;
    if (n < cmd->param_len)
        return DECODE_ERR;
    switch (cmd->opcode.ogf) {
    case BT_LINK_CTRL_CMD:
        return parse_link_ctrl(buf, n, cmd);
    case BT_LE_CTRL_CMD:
        return parse_le_ctrl(buf, n, cmd);
    default:
        break;
    }
    return NO_ERR;
}

static packet_error parse_event(unsigned char *buf, int n, struct bluetooth_hci_info *bt)
{
    struct bluetooth_hci_event *event;

    if (n < HCI_EVENT_HDR)
        return DECODE_ERR;
    event = mempool_alloc(sizeof(*event));
    bt->event = event;
    event->code = *buf++;
    event->param_len = *buf++;
    n -= HCI_EVENT_HDR;
    if (n < event->param_len)
        return DECODE_ERR;
    switch (event->code) {
    case BT_HCI_INQUIRY_COMPLETE:
        if (n < 1)
            return DECODE_ERR;
        event->param.status = *buf++;
        break;
    case BT_HCI_CMD_COMPLETE:
        if (n < 3)
            return DECODE_ERR;
        event->param.cmd = mempool_alloc(sizeof(*event->param.cmd));
        event->param.cmd->ncmdpkt = *buf++;
        event->param.cmd->opcode = read_uint16le(&buf);
        n -= 3;
        switch (event->param.cmd->opcode) {
        case BT_HCI_INQUIRY_CANCEL:
            if (n < 1)
                return DECODE_ERR;
            event->param.cmd->return_param = *buf++;
            break;
        default:
            break;
        }
        break;
    }
    return NO_ERR;
}

packet_error handle_bt(struct protocol_info *pinfo, unsigned char *buf,
                       int n, struct packet_data *pdata)
{
    struct bluetooth_hci_info *bt;

    if (n < BT_WITH_PHDR)
        return DECODE_ERR;
    bt = mempool_alloc(sizeof(*bt));
    bt->direction = read_uint32le(&buf);
    n -= 4;
    bt->type = *buf++;
    n--;
    pdata->data = bt;
    switch (bt->type) {
    case BT_HCI_COMMAND:
        return parse_cmd(buf, n, bt);
    case BT_HCI_ACL_DATA:
    case BT_HCI_SYNC_DATA:
    case BT_HCI_EVENT:
        return parse_event(buf, n, bt);
    case BT_HCI_ISO_DATA:
        break;
    }
    return NO_ERR;
}
