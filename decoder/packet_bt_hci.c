#include "packet_bt_hci.h"
#include "packet.h"
#include "util.h"
#include "string.h"

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

static const struct uint_string bt_hci_event[] = {
    { BT_HCI_INQUIRY_COMPLETE, "Inquiry Complete" },
    { BT_HCI_INQUIRY_RESULT, "Inquiry Result" },
    { BT_HCI_CONNECTION_COMPLETE, "Connection Complete" },
    { BT_HCI_CONNECTION_REQUEST, "Connection Request" },
    { BT_HCI_DISCONNECTION_COMPLETE, "Disconnection Complete" },
    { BT_HCI_AUTH_COMPLETE, "Authentication Complete" },
    { BT_HCI_REMOTE_NAME_REQ_COMPLETE, "Remote Name Request Complete" },
    { BT_HCI_ENCRYPTION_CHANGE, "Encryption Change" },
    { BT_HCI_CHANGE_CONN_LINK_KEY_COMPLETE, "Change Connection Link Key Complete" },
    { BT_HCI_MASTER_LINK_KEY_COMPLETE, "Master Link Key Complete" },
    { BT_HCI_READ_REM_SUP_FEAT_COMPLETE, "Read Remote Supported Features Complete" },
    { BT_HCI_READ_REM_VER_INF_COMPLETE, "Read Remote Version Information Complete" },
    { BT_HCI_QOS_SETUP_COMPLETE, "QOS Setup Complete" },
    { BT_HCI_CMD_COMPLETE, "Command Complete" },
    { BT_HCI_CMD_STATUS, "Command Status" },
    { BT_HCI_HW_ERR, "Hardware Error" },
    { BT_HCI_FLUSH_OCCURRED, "Flush Occurred" },
    { BT_HCI_ROLE_CHANGE, "Role Change" },
    { BT_HCI_NUM_COMPLETE_PKTS, "Number of Completed Packets" },
    { BT_HCI_MODE_CHANGE, "Mode Change" },
    { BT_HCI_RETURN_LINK_KEYS, "Return Link Keys" },
    { BT_HCI_PIN_CODE_REQ, "PIN Code Request" },
    { BT_HCI_LINK_KEY_REQ, "Link Key Request" },
    { BT_HCI_LINK_KEY_NOTIFICATION, "Link Key Notification" },
    { BT_HCI_LOOPBACK_CMD, "Loopback Command" },
    { BT_HCI_DATA_BUF_OVERFLOW, "Data Buffer Overflow" },
    { BT_HCI_MAX_SLOTS_CHANGE, "Max Slots Change" },
    { BT_HCI_READ_CLK_OFF_COMPLETE, "Read Clock Offset Complete" },
    { BT_HCI_CONN_PKT_TYPE_CHANGED, "Connection Packet Type Changed" },
    { BT_HCI_QOS_VIOLATION, "QOS Violation" },
    { BT_HCI_PAGE_SCAN_REP_MODE_CHANGE, "Page Scan Repetion Mode Change" },
    { BT_HCI_FLOW_SPEC_COMPLETE, "Flow Specification Complete" },
    { BT_HCI_INQ_RES_RSSI, "Inquiry Result with RSSI" },
    { BT_HCI_READ_REM_EXT_FEAT_COMPLETE, "Read Remote Extended Features Complete" },
    { BT_HCI_SYNC_CONN_COMPLETE, "Synchronous Connection Complete" },
    { BT_HCI_EXT_INQ_RESULT, "Extended Inquiry Result" },
    { BT_HCI_LE_META, "LE Meta" }
};

static const char *bt_hci_le_meta[] = {
    "",
    "LE Connection Complete",
    "LE Advertising Report",
    "LE Connection Update Complete",
    "LE Read Remote Features Complete",
    "LE Long Term Key Request",
    "LE Remote Connection Parameter Request",
    "LE Data Length Change",
    "LE Read Local P-256 Public Key Complete",
    "LE Generate DHKey Complete",
    "LE Enhanced Connection Complete",
    "LE Direct Advertising Report",
    "LE PHY Update Complete",
    "LE Extended Advertising Report",
    "LE Periodic Advertising Sync Established"
};

#define LINK_CTRL_CMD(x) \
    { (x) | BT_HCI_INQUIRY, "Inquiry" },                   \
    { (x) | BT_HCI_INQUIRY_CANCEL, "Inquiry Cancel" },     \
    { (x) | BT_HCI_PERIODIC_INQUIRY_MODE, "Periodic Inquiry Mode" }, \
    { (x) | BT_HCI_EXIT_PERIODIC_INQUIRY_MODE, "Exit Periodic Inquiry Mode" }, \
    { (x) | BT_HCI_CREATE_CONNECTION, "Create Connection" }, \
    { (x) | BT_HCI_DISCONNECT, "Disconnect" },             \
    { (x) | BT_HCI_CREATE_CONNECTION_CANCEL, "Create Connction Cancel" }, \
    { (x) | BT_HCI_ACCEPT_CONN_REQ, "Accept Connection Request" }, \
    { (x) | BT_HCO_REJECT_CONN_REQ, "Reject Connection Request" }, \
    { (x) | BT_HCI_LINK_KEY_REQ_REPLY, "Link Key Request Reply" }, \
    { (x) | BT_HCI_LINK_KEY_REQ_NEG_REPLY, "Link Key Request Negative Reply" }, \
    { (x) | BT_HCI_PIN_CODE_REQ_REPLY, "PIN Code Request Reply" }, \
    { (x) | BT_HCI_PIN_CODE_REQ_NEG_REPLY, "PIN Code Request Negative Reply" }, \
    { (x) | BT_HCI_CHANGE_CONN_PKT_TYPE, "Change Connection Packet Type" }, \
    { (x) | BT_HCI_AUTH_REQUESTED, "Authentication Requested" }, \
    { (x) | BT_HCI_SET_CONN_ENCRYPTION, "Set Connection Encryption" }, \
    { (x) | BT_HCI_CHANGE_CONN_LINK_KEY, "Change Connection Link Key" }, \
    { (x) | BT_HCI_LINK_KEY_SELECTION, "Link Key Selection" }

#define LINK_POLICY_CMD(x) \
    { (x) | BT_HCI_HOLD_MODE, "Hold Mode" }, \
    { (x) | BT_HCI_SNIFF_MODE, "Sniff Mode" }, \
    { (x) | BT_HCI_EXIT_SNIFF_MODE, "Exit Sniff Mode" }, \
    { (x) | BT_HCI_QOS_SETUP, "QOS Setup" }, \
    { (x) | BT_HCI_ROLE_DISC, "Role Discovery" }, \
    { (x) | BT_HCI_SWITCH_ROLE, "Switch Role" }, \
    { (x) | BT_HCI_READ_LINK_POL_SET, "Read Link Policy Settings" }, \
    { (x) | BT_HCI_WRITE_LINK_POL_SET, "Write Link Policy Settings" }, \
    { (x) | BT_HCI_READ_DEF_LINK_POL_SET, "Read Default Link Policy Settings" }, \
    { (x) | BT_HCI_WRITE_DEF_LINK_POL_SET, "Write Default Link Policy Settings" }, \
    { (x) | BT_HCI_FLOW_SPEC, "Flow Specification" }, \
    { (x) | BT_HCI_SNIFF_SUBRAT, "Sniff Subrating" }

#define CTRL_BB_CMD(x) \
    { (x) | BT_HCI_SET_EVENT_MASK, "Set Event Mask" }, \
    { (x) | BT_HCI_RESET, "Reset" }, \
    { (x) | BT_HCI_SET_EVENT_FILTER, "Set Event Filter" }, \
    { (x) | BT_HCI_FLUSH, "Flush" }, \
    { (x) | BT_HCI_READ_PIN_TYPE, "Read PIN Type" }, \
    { (x) | BT_HCI_WRITE_PIN_TYPE, "Write PIN Type" }, \
    { (x) | BT_HCI_READ_STORED_LINK_KEY, "Read Stored Link Key" }, \
    { (x) | BT_HCI_WRITE_STORED_LINK_KEY, "Write Stored Link Key" }, \
    { (x) | BT_HCI_DELETE_STORED_LINK_KEY, "Delete Stored Link Key" }, \
    { (x) | BT_HCI_WRITE_LOC_NAME, "Write Local Name" }, \
    { (x) | BT_HCI_READ_LOC_NAME,  "Read Local Name" }, \
    { (x) | BT_HCI_READ_CONN_ACCEPT_TIMEOUT, "Read Connection Accept Timeout" }, \
    { (x) | BT_HCI_WRITE_CONN_ACCEPT_TIMEOUT, "Write Connection Accept Timeout" }, \
    { (x) | BT_HCI_READ_PAGE_TIMEOUT, "Read Page Timeout" }, \
    { (x) | BT_HCI_WRITE_PAGE_TIMEOUT, "Write Page Timeout" }, \
    { (x) | BT_HCI_READ_SCAN_ENABLE, "Read Scan Enable" }, \
    { (x) | BT_HCI_WRITE_SCAN_ENABLE, "Write Scan Enable" }, \
    { (x) | BT_HCI_READ_PAGE_SCAN_ACTIVITY, "Read Page Scan Activity" }, \
    { (x) | BT_HCI_WRITE_PAGE_SCAN_ACTIVITY, "Write Page Scan Activity" }, \
    { (x) | BT_HCI_READ_INQ_SCAN_ACTIVITY, "Read Inquiry Scan Activity" }, \
    { (x) | BT_HCI_WRITE_INQ_SCAN_ACTIVITY, "Write Inquiry Scan Activity" }, \
    { (x) | BT_HCI_READ_AUTH_ENABLE, "Read Authentication Enable" }, \
    { (x) | BT_HCI_WRITE_AUTH_ENABLE, "Write Authentication Enable" }, \
    { (x) | BT_HCI_READ_ENC_MODE, "Read Encryption Mode" }, \
    { (x) | BT_HCI_WRITE_ENC_MODE, "Write Encryption Mode" }, \
    { (x) | BT_HCI_READ_COD, "Read Class of Device" }, \
    { (x) | BT_HCI_WRITE_COD, "Write Class of Device" }, \
    { (x) | BT_HCI_READ_VOICE_SETTING, "Read Voice Setting" }, \
    { (x) | BT_HCI_WRITE_VOICE_SETTING, "Write Voice Setting" }

#define INF_PARAMS(x) \
    { (x) | BT_HCI_READ_LOC_VERINF, "Read Local Version Information" }, \
    { (x) | BT_HCI_READ_LOC_SUP_CMDS, "Read Local Supported Commands" }, \
    { (x) | BT_HCI_READ_LOC_SUP_FEATURES, "Read Local Supported features" }, \
    { (x) | BT_HCI_READ_LOC_EXT_FEATURES, "Read Local Extended Features" }, \
    { (x) | BT_HCI_READ_BUF_SIZE, "Read Buffer Size" }, \
    { (x) | BT_HCI_READ_BD_ADDR, "Read BD_ADDR" }, \
    { (x) | BT_HCI_READ_DATA_BLOCK_SIZE,  "Read Data Block Size" }, \
    { (x) | BT_HCI_READ_LOC_SUP_CODECS_V1, "Read Local Suppored Codecs" }, \
    { (x) | BT_HCI_READ_LOC_SUP_CODECS_V2, "Read Local Suppored Codecs" }, \
    { (x) | BT_HCI_READ_LOC_SIMPLE_PAIRING_OPTS, "Read Local Simple Pairing Options" }, \
    { (x) | BT_HCI_READ_LOC_SUP_CODECS_CAP, "Read Local Suppored Codec Capabilities" }, \
    { (x) | BT_HCI_READ_LOC_SUP_CTRL_DELAY, "Read Local Suppored Controller Delay" }

#define LE_CTRL_CMD(x) \
    { (x) | BT_HCI_LE_SET_EVENT_MASK, "LE Set Event Mask" }, \
    { (x) | BT_HCI_LE_READ_BUFFER_SIZE_V1, "LE Read Buffer Size" }, \
    { (x) | BT_HCI_LE_READ_BUFFER_SIZE_V2, "LE Read Buffer Size" }, \
    { (x) | BT_HCI_LE_READ_LOC_SUPPORTED_FEATURES, "LE Read Local Supported Features" }, \
    { (x) | BT_HCI_LE_SET_RANDOM_ADDR, "LE Set Random Address" }, \
    { (x) | BT_HCI_LE_SET_ADV_PARAMS, "LE Set Extended Scan Parameters" }, \
    { (x) | BT_HCI_LE_SET_EXTENDED_SCAN_PARAMS, "LE Set Extended Scan Parameters" }, \
    { (x) | BT_HCI_LE_SET_EXTENDED_SCAN_ENABLE, "LE Set Extended Scan Enable" }

static char *bt_hci_ogf[] = {
    "",
    "Link Control Commands",
    "Link Policy Commands",
    "Controller and Baseband Commands",
    "Informational Parameters",
    "Status Parameters",
    "Testing Commands",
    "",
    "LE Controller Commands"
};

static const struct uint_string bt_hci_opcode[] = {
    LINK_CTRL_CMD(BT_LINK_CTRL_CMD),
    LINK_POLICY_CMD(BT_LINK_POLICY_CMD),
    CTRL_BB_CMD(BT_CTRL_BB_CMD),
    INF_PARAMS(BT_INF_PARAMS),
    LE_CTRL_CMD(BT_LE_CTRL_CMD)
};

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

static struct packet_flags opcode[] = {
    { "Opcode Group Field", 6, bt_hci_ogf },
    { "Opcode Command Field", 10, NULL }
};

struct packet_flags *get_bt_opcode_flags(void)
{
    return opcode;
}

int get_bt_opcode_flags_size(void)
{
    return ARRAY_SIZE(opcode);
}

char *get_bt_type(uint8_t type)
{
    switch (type) {
    case BT_HCI_COMMAND:
        return "HCI Command";
    case BT_HCI_ACL_DATA:
        return "HCI ACL Data";
    case BT_HCI_SYNC_DATA:
        return "HCI Synchronous Data";
    case BT_HCI_EVENT:
        return "HCI Event";
    case BT_HCI_ISO_DATA:
        return "HCI ISO Data";
    default:
        return "Unknown";
    }
}

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

static uint8_t *read_uint8_array(uint8_t nrep, unsigned char **buf, int *n)
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

static uint16_t *read_uint16_array(uint8_t nrep, unsigned char **buf, int *n)
{
    uint16_t *array;
    unsigned char *p = *buf;

    if (*n < 2 * nrep)
        return NULL;
    *n = *n - 2 * nrep;
    array = mempool_alloc(2 * nrep);
    for (unsigned int i = 0; i < nrep; i++)
        array[i] = read_uint16le(&p);
    *buf = p;
    return array;
}

static packet_error parse_le_ctrl(unsigned char *buf, int n, struct bluetooth_hci_cmd *cmd,
                                  struct packet_data *pdata)
{
    int bits;

    switch (GET_OCF(cmd->opcode)) {
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

static packet_error parse_link_ctrl(unsigned char *buf, int n, struct bluetooth_hci_cmd *cmd,
                                    struct packet_data *pdata)
{
    switch (GET_OCF(cmd->opcode)) {
    case BT_HCI_INQUIRY:
        if (n < 5) {
            pdata->error = create_error_string("Packet length (%d) less than HCI Inquiry packet (5)", n);
            return DECODE_ERR;
        }
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

static packet_error parse_ctrl_bb_cmd(unsigned char *buf, int n, struct bluetooth_hci_cmd *cmd,
                                      struct packet_data *pdata)
{
    switch (GET_OCF(cmd->opcode)) {
    case BT_HCI_READ_ENC_MODE:
        if (n < 2)
            return DECODE_ERR;
        cmd->param.mode = mempool_alloc(sizeof(*cmd->param.mode));
        cmd->param.mode->status = *buf++;
        cmd->param.mode->mode = *buf++;
        break;
    case BT_HCI_WRITE_ENC_MODE:
        if (n < 2)
            return DECODE_ERR;
        cmd->param.mode = mempool_alloc(sizeof(*cmd->param.mode));
        cmd->param.mode->mode = *buf++;
        cmd->param.mode->status = *buf++;
        break;
    default:
        break;
    }
    return NO_ERR;
}

static packet_error parse_inf_params(unsigned char *buf, int n, struct bluetooth_hci_cmd *cmd,
                                     struct packet_data *pdata)
{
    switch (GET_OCF(cmd->opcode)) {
    case BT_HCI_READ_LOC_VERINF:
    case BT_HCI_READ_LOC_SUP_CMDS:
        break;
    case BT_HCI_READ_LOC_SUP_FEATURES:
        if (n < 9)
            return DECODE_ERR;
        cmd->param.feat = mempool_alloc(sizeof(*cmd->param.feat));
        cmd->param.feat->status = *buf++;
        cmd->param.feat->lmp_features = read_uint64le(&buf);
        break;
    case BT_HCI_READ_LOC_EXT_FEATURES:
    case BT_HCI_READ_BUF_SIZE:
    case BT_HCI_READ_BD_ADDR:
    case BT_HCI_READ_DATA_BLOCK_SIZE:
    case BT_HCI_READ_LOC_SUP_CODECS_V1:
    case BT_HCI_READ_LOC_SUP_CODECS_V2:
    case BT_HCI_READ_LOC_SIMPLE_PAIRING_OPTS:
    case BT_HCI_READ_LOC_SUP_CODECS_CAP:
    case BT_HCI_READ_LOC_SUP_CTRL_DELAY:
    default:
        break;
    }
    return NO_ERR;
}

static packet_error parse_cmd(unsigned char *buf, int n, struct bluetooth_hci_info *bt,
                              struct packet_data *pdata)
{
    struct bluetooth_hci_cmd *cmd;

    if (n < HCI_CMD_HDR) {
        pdata->error = create_error_string("Packet length (%d) less than minimum HCI cmd header", n);
        return DECODE_ERR;
    }
    cmd = mempool_alloc(sizeof(*cmd));
    bt->cmd = cmd;
    cmd->opcode = read_uint16le(&buf);
    n -= 2;
    cmd->param_len = *buf++;
    n--;
    if (n < cmd->param_len) {
        pdata->error = create_error_string("Packet length (%d) less than parameter length (%u)",
                                           n, cmd->param_len);
        return DECODE_ERR;
    }
    switch (GET_OGF(cmd->opcode)) {
    case BT_LINK_CTRL_CMD:
        return parse_link_ctrl(buf, n, cmd, pdata);
    case BT_CTRL_BB_CMD:
        return parse_ctrl_bb_cmd(buf, n, cmd, pdata);
    case BT_INF_PARAMS:
        return parse_inf_params(buf, n, cmd, pdata);
    case BT_LE_CTRL_CMD:
        return parse_le_ctrl(buf, n, cmd, pdata);
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
        meta->rep = mempool_calloc(1, struct hci_le_adv_report);
        meta->rep->nrep = *buf++;
        if (meta->rep->nrep < 1 || meta->rep->nrep > 0x19)
            return DECODE_ERR;
        n--;
        meta->rep->event_type = read_uint8_array(meta->rep->nrep, &buf, &n);
        if (meta->rep->event_type == NULL)
            return DECODE_ERR;
        meta->rep->addr_type = read_uint8_array(meta->rep->nrep, &buf, &n);
        if (meta->rep->event_type == NULL)
            return DECODE_ERR;
        if (n < 6 * meta->rep->nrep)
            return DECODE_ERR;
        n = n - meta->rep->nrep * 6;
        meta->rep->addr = mempool_alloc(6 * meta->rep->nrep);
        for (int i = 0; i < meta->rep->nrep; i++)
            READ_BDADDR(meta->rep->addr, buf);
        meta->rep->len_data = read_uint8_array(meta->rep->nrep, &buf, &n);
        if (meta->rep->len_data == NULL)
            return DECODE_ERR;
        meta->rep->rssi = read_uint8_array(meta->rep->nrep, &buf, &n);
        if (meta->rep->rssi == NULL)
            return DECODE_ERR;
        break;
    case BT_HCI_LE_EXT_ADV_REPORT:
        if (n < 1)
            return DECODE_ERR;
        meta->erep = mempool_calloc(1, struct hci_le_ext_adv_report);
        meta->erep->nrep = *buf++;
        if (meta->erep->nrep < 1 || meta->erep->nrep > 0xa)
            return DECODE_ERR;
        n--;
        meta->erep->event_type = read_uint16_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->event_type == NULL)
            return DECODE_ERR;
        meta->erep->addr_type = read_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->addr_type == NULL)
            return DECODE_ERR;
        if (n < 6 * meta->erep->nrep)
            return DECODE_ERR;
        n = n - meta->erep->nrep * 6;
        meta->erep->addr = mempool_alloc(6 * meta->erep->nrep);
        for (int i = 0; i < meta->erep->nrep; i++)
            READ_BDADDR(meta->erep->addr, buf);
        meta->erep->primary_phy = read_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->primary_phy == NULL)
            return DECODE_ERR;
        meta->erep->secondary_phy = read_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->secondary_phy == NULL)
            return DECODE_ERR;
        meta->erep->adv_sid = read_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->adv_sid == NULL)
            return DECODE_ERR;
        meta->erep->tx_power = read_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->tx_power == NULL)
            return DECODE_ERR;
        meta->erep->rssi = read_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->rssi == NULL)
            return DECODE_ERR;
        meta->erep->padv_ivl = read_uint16_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->padv_ivl == NULL)
            return DECODE_ERR;
        meta->erep->daddr_type = read_uint8_array(meta->erep->nrep, &buf, &n);
        if (meta->erep->daddr_type == NULL)
            return DECODE_ERR;
        if (n < 6 * meta->erep->nrep)
            return DECODE_ERR;
        n = n - meta->erep->nrep * 6;
        meta->erep->daddr = mempool_alloc(6 * meta->erep->nrep);
        for (int i = 0; i < meta->erep->nrep; i++)
            READ_BDADDR(meta->erep->daddr, buf);
        meta->erep->data_len = read_uint8_array(meta->erep->nrep, &buf, &n);
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

static packet_error parse_event(unsigned char *buf, int n, struct bluetooth_hci_info *bt,
                                struct packet_data *pdata)
{
    struct bluetooth_hci_event *event;

    if (n < HCI_EVENT_HDR) {
        pdata->error = create_error_string("Packet length (%d) less than minimum HCI event header", n);
        return DECODE_ERR;
    }
    event = mempool_alloc(sizeof(*event));
    bt->event = event;
    event->code = *buf++;
    event->param_len = *buf++;
    n -= HCI_EVENT_HDR;
    if (n < event->param_len) {
        pdata->error = create_error_string("Packet length (%d) less than parameter length (%u)",
                                           n, event->param_len);
        return DECODE_ERR;
    }
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
        switch (GET_OGF(event->param.cmd->opcode)) {
        case BT_LINK_CTRL_CMD:
            switch (GET_OCF(event->param.cmd->opcode)) {
            case BT_HCI_INQUIRY_CANCEL:
                if (n < 1)
                    return DECODE_ERR;
                event->param.cmd->return_param = *buf++;
                break;
            default:
                break;
            }
            break;
        case BT_LE_CTRL_CMD:
            switch (GET_OCF(event->param.cmd->opcode)) {
            case BT_HCI_LE_SET_RANDOM_ADDR:
                if (n < 1)
                    return DECODE_ERR;
                event->param.cmd->return_param = *buf++;
                break;
            default:
                break;
            }
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

packet_error parse_bt(unsigned char *buf, int n, struct bluetooth_hci_info *bt,
                      struct packet_data *pdata)
{
    bt->type = *buf++;
    n--;
    switch (bt->type) {
    case BT_HCI_COMMAND:
        return parse_cmd(buf, n, bt, pdata);
    case BT_HCI_ACL_DATA:
    case BT_HCI_SYNC_DATA:
    case BT_HCI_EVENT:
        return parse_event(buf, n, bt, pdata);
    case BT_HCI_ISO_DATA:
    default:
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
    pdata->len = n;
    bt->direction = read_uint32le(&buf);
    n -= 4;
    return parse_bt(buf, n, bt, pdata);
}


packet_error handle_bt(struct protocol_info *pinfo, unsigned char *buf,
                       int n, struct packet_data *pdata)
{
    struct bluetooth_hci_info *bt;

    if (n < 1)
        return DECODE_ERR;
    bt = mempool_alloc(sizeof(*bt));
    pdata->data = bt;
    pdata->len = n;
    bt->direction = 0;
    return parse_bt(buf, n, bt, pdata);
}

static char *get_bt_cmd_string(char *buf, size_t n, struct bluetooth_hci_cmd *cmd)
{
    struct uint_string key;
    struct uint_string *res;

    key.val = cmd->opcode;
    res = bsearch(&key, bt_hci_opcode, ARRAY_SIZE(bt_hci_opcode),
                  sizeof(struct uint_string), cmp_val);
    if (!res)
        goto error;
    snprintcat(buf, n, "Command %s", res->str);
    switch (GET_OGF(cmd->opcode)) {
    case BT_LINK_CTRL_CMD:
        switch (GET_OCF(cmd->opcode)) {
        case BT_HCI_INQUIRY:
            if (cmd->param.inq)
                snprintcat(buf, n, ": LAP: " LAPSTR "  Inquiry Length: %u  Number of Responses: %u",
                           LAP2STR(cmd->param.inq->lap), cmd->param.inq->inquiry_len,
                           cmd->param.inq->nresp);
            return buf;
        default:
            break;
        }
        break;
    case BT_LE_CTRL_CMD:
        switch (GET_OCF(cmd->opcode)) {
        case BT_HCI_LE_SET_RANDOM_ADDR:
            snprintcat(buf, n, ": " HWSTR, HW2STR(cmd->param.random_addr));
            return buf;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return buf;

error:
    snprintcat(buf, n, "Command Unknown");
    return buf;
}

static char *get_bt_event_string(char *buf, size_t n, struct bluetooth_hci_event *event)
{
    snprintcat(buf, n, "Event   %s", get_bt_event_code(event->code));
    switch (event->code) {
    case BT_HCI_CMD_COMPLETE:
        if (event->param.cstat)
            snprintcat(buf, n, ": %s", get_bt_command(event->param.cstat->opcode));
        return buf;
    case BT_HCI_CMD_STATUS:
        if (event->param.cmd)
            snprintcat(buf, n, ": %s", get_bt_command(event->param.cmd->opcode));
        return buf;
    case BT_HCI_LE_META:
        if (event->param.meta.subevent_code > ARRAY_SIZE(bt_hci_le_meta))
            snprintcat(buf, n, ": Unknown");
        else
            snprintcat(buf, n, ": %s", bt_hci_le_meta[event->param.meta.subevent_code]);
        return buf;
    default:
        return buf;
    }
    snprintcat(buf, n, "Event   Unknown");
    return buf;
}

char *bt2string(char *buf, size_t n, struct bluetooth_hci_info *bt)
{
    switch (bt->type) {
    case BT_HCI_COMMAND:
        if (!bt->cmd)
            goto error;
        return get_bt_cmd_string(buf, n, bt->cmd);
    case BT_HCI_EVENT:
        if (!bt->event)
            goto error;
        return get_bt_event_string(buf, n, bt->event);
    default:
        break;
    }
error:
    snprintcat(buf, n, "Unknown");
    return buf;
}

char *get_bt_command(uint16_t opcode)
{
    struct uint_string key;
    struct uint_string *res;

    key.val = opcode;
    res = bsearch(&key, bt_hci_opcode, ARRAY_SIZE(bt_hci_opcode),
                  sizeof(struct uint_string), cmp_val);
    if (!res)
        return "Unknown";
    return res->str;
}

char *get_bt_event_code(uint8_t code)
{
    struct uint_string key;
    struct uint_string *res;

    key.val = code;
    res = bsearch(&key, bt_hci_event, ARRAY_SIZE(bt_hci_event),
                  sizeof(struct uint_string), cmp_val);
    if (!res)
        return "Unknown";
    return res->str;
}

char *get_bt_error_string(uint8_t error_code)
{
    switch (error_code) {
    case 0x00:
        return "Success";
    case 0x01:
        return "Unknown HCI Command";
    case 0x02:
        return "Unknown Connection Identifier";
    case 0x03:
        return "Hardware Failure";
    case 0x04:
        return "Page Timeout";
    case 0x05:
        return "Authentication Failure";
    case 0x06:
        return "PIN or Key Missing";
    case 0x07:
        return "Memory Capacity Exceeded";
    case 0x08:
        return "Connection Timeout";
    case 0x09:
        return "Connection Limit Exceeded";
    case 0x0A:
        return "Synchronous Connection Limit To A Device Exceeded";
    case 0x0B:
        return "Connection Already Exists";
    case 0x0C:
        return "Command Disallowed";
    case 0x0D:
        return "Connection Rejected due to Limited Resources";
    case 0x0E:
        return "Connection Rejected Due To Security Reasons";
    case 0x0F:
        return "Connection Rejected due to Unacceptable BD_ADDR";
    case 0x10:
        return "Connection Accept Timeout Exceeded";
    case 0x11:
        return "Unsupported Feature or Parameter Value";
    case 0x12:
        return "Invalid HCI Command Parameters";
    case 0x13:
        return "Remote User Terminated Connection";
    case 0x14:
        return "Remote Device Terminated Connection due to Low Resources";
    case 0x15:
        return "Remote Device Terminated Connection due to Power Off";
    case 0x16:
        return "Connection Terminated By Local Host";
    case 0x17:
        return "Repeated Attempts";
    case 0x18:
        return "Pairing Not Allowed";
    case 0x19:
        return "Unknown LMP PDU";
    case 0x1A:
        return "Unsupported Remote Feature";
    case 0x1B:
        return "SCO Offset Rejected";
    case 0x1C:
        return "SCO Interval Rejected";
    case 0x1D:
        return "SCO Air Mode Rejected";
    case 0x1E:
        return "Invalid LMP Parameters / Invalid LL Parameters";
    case 0x1F:
        return "Unspecified Error";
    case 0x20:
        return "Unsupported LMP Parameter Value / Unsupported LL Parameter Value";
    case 0x21:
        return "Role Change Not Allowed";
    case 0x22:
        return "LMP Response Timeout / LL Response Timeout";
    case 0x23:
        return "LMP Error Transaction Collision / LL Procedure Collision";
    case 0x24:
        return "LMP PDU Not Allowed";
    case 0x25:
        return "Encryption Mode Not Acceptable";
    case 0x26:
        return "Link Key cannot be Changed";
    case 0x27:
        return "Requested QoS Not Supported";
    case 0x28:
        return "Instant Passed";
    case 0x29:
        return "Pairing With Unit Key Not Supported";
    case 0x2A:
        return "Different Transaction Collision";
    case 0x2B:
        return "Reserved for future use";
    case 0x2C:
        return "QoS Unacceptable Parameter";
    case 0x2D:
        return "QoS Rejected";
    case 0x2E:
        return "Channel Classification Not Supported";
    case 0x2F:
        return "Insufficient Security";
    case 0x30:
        return "Parameter Out Of Mandatory Range";
    case 0x31:
        return "Reserved for future use";
    case 0x32:
        return "Role Switch Pending";
    case 0x33:
        return "Reserved for future use";
    case 0x34:
        return "Reserved Slot Violation";
    case 0x35:
        return "Role Switch Failed";
    case 0x36:
        return "Extended Inquiry Response Too Large";
    case 0x37:
        return "Secure Simple Pairing Not Supported By Host";
    case 0x38:
        return "Host Busy - Pairing";
    case 0x39:
        return "Connection Rejected due to No Suitable Channel Found";
    case 0x3A:
        return "Controller Busy";
    case 0x3B:
        return "Unacceptable Connection Parameters";
    case 0x3C:
        return "Advertising Timeout";
    case 0x3D:
        return "Connection Terminated due to MIC Failure";
    case 0x3E:
        return "Connection Failed to be Established / Synchronization Timeout";
    case 0x3F:
        return "Previously used";
    case 0x40:
        return "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging";
    case 0x41:
        return "Type0 Submap Not Defined";
    case 0x42:
        return "Unknown Advertising Identifier";
    case 0x43:
        return "Limit Reached";
    case 0x44:
        return "Operation Cancelled by Host";
    case 0x45:
        return "Packet Too Long";
    case 0x46:
        return "Too Late";
    case 0x47:
        return "Too Early";
    default:
        return "Unknown Error";
    }
}
