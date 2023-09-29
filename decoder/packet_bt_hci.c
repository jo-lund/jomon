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
        (s) += 6;           \
    } while (0);

extern void add_bt_information(void *w, void *sw, void *data);
extern void print_bt(char *buf, int n, void *data);
static packet_error handle_bt(struct protocol_info *pinfo, unsigned char *buf,
                              int n, struct packet_data *pdata);
packet_error handle_bt_phdr(struct protocol_info *pinfo, unsigned char *buf,
                            int n, struct packet_data *pdata);

static struct protocol_info bt_hci = {
    .short_name = "BT HCI",
    .long_name = "Bluetooth HCI",
    .decode = handle_bt,
    .print_pdu = print_bt,
    .add_pdu = add_bt_information
};

static struct protocol_info bt_hci_phdr = {
    .short_name = "BT HCI",
    .long_name = "Bluetooth HCI",
    .decode = handle_bt_phdr,
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
    register_protocol(&bt_hci, DATALINK, LINKTYPE_BT_HCI_H4);
    register_protocol(&bt_hci_phdr, DATALINK, LINKTYPE_BT_HCI_H4_WITH_PHDR);
}

static uint8_t *create_uint8_array(uint8_t nrep, unsigned char **buf, int *n)
{
    uint8_t *array;
    unsigned char *p = *buf;

    if (*n < nrep)
        return NULL;
    *n -= nrep;
    array = mempool_alloc(nrep);
    for (unsigned int i = 0; i < nrep; i++)
        array[i] = *p++;
    *buf = p;
    return array;
}

static uint16_t *create_uint16_array(uint8_t nrep, unsigned char **buf, int *n)
{
    uint16_t *array;
    unsigned char *p = *buf;

    if (*n < 2 * nrep)
        return NULL;
    *n = *n - 2 * nrep;
    array = mempool_alloc(2 * nrep);
    for (unsigned int i = 0; i < 2 * nrep; i++)
        array[i] = read_uint16le(&p);
    *buf = p;
    return array;
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

static packet_error parse_le_meta(unsigned char *buf, int n, struct hci_le_meta *meta)
{
    int sum = 0;

    meta->subevent_code = *buf++;
    n--;
    switch (meta->subevent_code) {
    case BT_HCI_LE_ADV_REPORT:
        if (n < 1)
            return DECODE_ERR;
        meta->rep = mempool_alloc(sizeof(*meta->rep));
        meta->rep->nrep = *buf++;
        n--;
        meta->rep->event_type = create_uint8_array(meta->rep->nrep, &buf, &n);
        if (meta->rep->event_type == NULL)
            return DECODE_ERR;
        meta->rep->addr_type = create_uint8_array(meta->rep->nrep, &buf, &n);
        if (meta->rep->event_type == NULL)
            return DECODE_ERR;
        if (n < 6 * meta->rep->nrep)
            return DECODE_ERR;
        n = n - meta->rep->nrep * 6;
        meta->rep->addr = mempool_alloc(6 * meta->rep->nrep);
        for (int i = 0; i < meta->rep->nrep; i++)
            READ_BDADDR(meta->rep->addr, buf);
        meta->rep->len_data = create_uint8_array(meta->rep->nrep, &buf, &n);
        if (meta->rep->len_data == NULL)
            return DECODE_ERR;
        meta->rep->rssi = create_uint8_array(meta->rep->nrep, &buf, &n);
        if (meta->rep->rssi == NULL)
            return DECODE_ERR;
        break;
    case BT_HCI_LE_EXT_ADV_REPORT:
        if (n < 1)
            return DECODE_ERR;
        meta->erep = mempool_alloc(sizeof(*meta->erep));
        meta->erep->nrep = *buf++;
        n--;
        meta->erep->event_type = create_uint16_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->event_type == NULL)
            return DECODE_ERR;
        meta->erep->addr_type = create_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->addr_type == NULL)
            return DECODE_ERR;
        if (n < 6 * meta->erep->nrep)
            return DECODE_ERR;
        n = n - meta->erep->nrep * 6;
        meta->erep->addr = mempool_alloc(6 * meta->erep->nrep);
        for (int i = 0; i < meta->erep->nrep; i++)
            READ_BDADDR(meta->erep->addr, buf);
        meta->erep->primary_phy = create_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->primary_phy == NULL)
            return DECODE_ERR;
        meta->erep->secondary_phy = create_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->secondary_phy == NULL)
            return DECODE_ERR;
        meta->erep->adv_sid = create_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->adv_sid == NULL)
            return DECODE_ERR;
        meta->erep->tx_power = create_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->tx_power == NULL)
            return DECODE_ERR;
        meta->erep->rssi = create_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->rssi == NULL)
            return DECODE_ERR;
        meta->erep->padv_ivl = create_uint16_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->padv_ivl == NULL)
            return DECODE_ERR;
        meta->erep->daddr_type = create_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->daddr_type == NULL)
            return DECODE_ERR;
        if (n < 6 * meta->erep->nrep)
            return DECODE_ERR;
        n = n - meta->erep->nrep * 6;
        meta->erep->daddr = mempool_alloc(6 * meta->erep->nrep);
        for (int i = 0; i < meta->erep->nrep; i++)
            READ_BDADDR(meta->erep->daddr, buf);
        meta->erep->data_len = create_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->data_len == NULL)
            return DECODE_ERR;
        for (int i = 0; i < meta->erep->nrep; i++)
            sum += meta->erep->data_len[i];
        if (n < sum)
            return DECODE_ERR;
        /* TODO: Parse this data according to BT Core specification, vol.3, section 11 */
        meta->erep->data = mempool_copy(buf, sum);
        break;
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
    case BT_HCI_CMD_STATUS:
        if (n < 4)
            return DECODE_ERR;
        event->param.cstat = mempool_alloc(sizeof(*event->param.cstat));
        event->param.cstat->status = *buf++;
        event->param.cstat->ncmdpkt = *buf++;
        event->param.cstat->opcode = read_uint16le(&buf);
        break;
    case BT_HCI_EXT_INQ_RESULT:
        if (n < 255)
            return DECODE_ERR;
        event->param.res = mempool_alloc(sizeof(*event->param.res));
        event->param.res->nresp = *buf++;
        READ_BDADDR(event->param.res->addr, buf);
        event->param.res->pscan_rep_mode = *buf++;
        event->param.res->reserved = *buf++;
        event->param.res->cod[0] = buf[2];
        event->param.res->cod[1] = buf[1];
        event->param.res->cod[2] = buf[0];
        event->param.res->clock_off = read_uint16le(&buf);
        event->param.res->rssi = *buf++;
        /* TODO: Parse this data according to BT Core specification, vol.3, section 8 */
        memcpy(event->param.res->data, buf, 240);
        break;
    case BT_HCI_LE_META:
        if (n < 1)
            return DECODE_ERR;
        return parse_le_meta(buf, n, &event->param.meta);
    default:
        break;
    }
    return NO_ERR;
}

packet_error parse_bt(unsigned char *buf, int n, struct bluetooth_hci_info *bt)
{
    bt->type = *buf++;
    n--;
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

packet_error handle_bt_phdr(struct protocol_info *pinfo, unsigned char *buf,
                            int n, struct packet_data *pdata)
{
    struct bluetooth_hci_info *bt;

    if (n < BT_WITH_PHDR)
        return DECODE_ERR;
    bt = mempool_alloc(sizeof(*bt));
    pdata->data = bt;
    bt->direction = read_uint32le(&buf);
    n -= 4;
    return parse_bt(buf, n, bt);
}


packet_error handle_bt(struct protocol_info *pinfo, unsigned char *buf,
                       int n, struct packet_data *pdata)
{
    struct bluetooth_hci_info *bt;

    if (n < 1)
        return DECODE_ERR;
    bt = mempool_alloc(sizeof(*bt));
    pdata->data = bt;
    bt->direction = 0;
    return parse_bt(buf, n, bt);
}
