#ifndef PACKET_BT
#define PACKET_BT

#include <stdint.h>

#define LAPSTR "%02x:%02x:%02x"
#define LAP2STR(x) (x)[0], (x)[1], (x)[2]

#define BT_HCI_COMMAND 1
#define BT_HCI_ACL_DATA 2
#define BT_HCI_SYNC_DATA 3
#define BT_HCI_EVENT 4
#define BT_HCI_ISO_DATA 5

#define BT_LINK_CTRL_CMD 0x1
enum hci_link_ctrl_commands {
    BT_HCI_INQUIRY = 0x0001,
    BT_HCI_INQUIRY_CANCEL = 0x0002,
    BT_HCI_PERIODIC_INQUIRY_MODE = 0x0003,
    BT_HCI_EXIT_PERIODIC_INQUIRY_MODE = 0x0004,
    BT_HCI_CREATE_CONNECTION = 0x0005,
    BT_HCI_DISCONNECT = 0x0006,
    BT_HCI_CREATE_CONNECTION_CANCEL = 0x0008,
    BT_HCI_ACCEPT_CONN_REQ = 0x0009,
    BT_HCO_REJECT_CONN_REQ = 0x000a,
    BT_HCI_LINK_KEY_REQ_REPLY = 0x000b,
    BT_HCI_LINK_KEY_REQ_NEG_REPLY = 0x000c,
    BT_HCI_PIN_CODE_REQ_REPLY = 0x000d,
    BT_HCI_PIN_CODE_REQ_NEG_REPLY = 0x000e,
    BT_HCI_CHANGE_CONN_PKT_TYPE = 0x000f,
    BT_HCI_AUTH_REQUESTED = 0x0011,
    BT_HCI_SET_CONN_ENCRYPTION = 0x0013,
    BT_HCI_CHANGE_CONN_LINK_KEY = 0x0015,
    BT_HCI_LINK_KEY_SELECTION = 0x0017,
};

#define BT_LE_CTRL_CMD 0x8
enum hci_le_ctrl_commands {
    BT_HCI_LE_SET_EVENT_MASK = 0x0001,
    BT_HCI_LE_READ_BUFFER_SIZE_V1 = 0x0002,
    BT_HCI_LE_READ_BUFFER_SIZE_V2 = 0x0060,
    BT_HCI_LE_READ_LOC_SUPPORTED_FEATURES = 0x0003,
    BT_HCI_LE_SET_RANDOM_ADDR = 0x0005,
    BT_HCI_LE_SET_ADV_PARAMS = 0x0006,
    BT_HCI_LE_SET_EXTENDED_SCAN_PARAMS = 0x0041,
    BT_HCI_LE_SET_EXTENDED_SCAN_ENABLE = 0x0042,
};

enum hci_own_address_type {
    BT_HCI_PUBLIC_DEVICE_ADDRESS,
    BT_HCI_RANDOM_DEVICE_ADDRESS,
    BT_HCI_RESOLVABLE_PRIVATE_ADDRESS_PUB,
    BT_HCI_RESOLVABLE_PRIVATE_ADDRESS_SET_RANDOM
};

enum hci_scanning_filter_policy {
    BT_HCI_BASIC_UNFILTERED,
    BT_HCI_BASIC_FILTERED,
    BT_HCI_EXTENDED_UNFILTERED,
    BT_HCI_EXTENDED_FILTERED
};

enum hci_scan_type {
    BT_HCI_PASSIVE,
    BT_HCI_ACTIVE
};

enum hci_event_code {
    BT_HCI_INQUIRY_COMPLETE = 0x1,
    BT_HCI_INQUIRY_RESULT = 0x2,
    BT_HCI_CMD_COMPLETE = 0xe,
    BT_HCI_CMD_STATUS = 0xf,
    BT_HCI_EXT_INQ_RESULT = 0x2f,
    BT_HCI_LE_META = 0x3e,
};

enum hci_le_meta_event {
    BT_HCI_LE_CONN_COMPLETE = 0x1,
    BT_HCI_LE_ADV_REPORT,
    BT_HCI_LE_CONN_UPDATE,
    BT_HCI_LE_READ_REMOTE_COMPLETE,
    BT_HCI_LE_LONG_TERM_KEY_REQ,
    BT_HCI_LE_REMOTE_CONN_PARAM_REQ,
    BT_HCI_LE_DATA_LEN_CHANGE,
    BT_HCI_LE_READ_LOC_PUB_KEY_COMPLETE,
    BT_HCI_LE_GEN_DHKEY_COMPLETE,
    BT_HCI_LE_ENHANCED_CONN_COMPLETE,
    BT_HCI_LE_DIRECT_ADV_REPORT,
    BT_HCI_LE_PHY_UPDATE_COMPLETE,
    BT_HCI_LE_EXT_ADV_REPORT
};

struct hci_set_extended_scan_params {
    uint8_t own_address_type;
    uint8_t scanning_filter_policy;
    struct {
        unsigned int le_1m : 1;
        unsigned int le_coded : 1;
    } scanning_phy;
    uint8_t *scan_type;
    uint16_t *scan_interval;
    uint16_t *scan_window;
};

struct hci_set_extended_scan_enable {
    uint8_t enable;
    uint8_t filter_dup;
    uint16_t duration;
    uint16_t period;
};

struct hci_inquiry {
    uint8_t lap[3];
    uint8_t inquiry_len;
    uint8_t nresp;
};

struct hci_cmd_complete {
    uint8_t ncmdpkt;
    uint16_t opcode;
    uint8_t return_param; /* size depends on command — check max size */
};

struct hci_cmd_status {
    uint8_t status;
    uint8_t ncmdpkt;
    uint16_t opcode;
};

struct hci_le_adv_report {
    uint8_t nrep;
    uint8_t *event_type;
    uint8_t *addr_type;
    uint8_t *addr;
    uint8_t *len_data;
    uint8_t *rssi;
};

struct hci_le_ext_adv_report {
    uint8_t nrep;
    uint16_t *event_type;
    uint8_t *addr_type;
    uint8_t *addr;
    uint8_t *primary_phy;
    uint8_t *secondary_phy;
    uint8_t *adv_sid;
    uint8_t *tx_power;
    uint8_t *rssi;
    uint16_t *padv_ivl;
    uint8_t *daddr_type;
    uint8_t *daddr;
    uint8_t *data_len;
    unsigned char *data;
};

struct hci_ext_inq_result {
    uint8_t nresp;
    uint8_t addr[6];
    uint8_t pscan_rep_mode;
    uint8_t reserved;
    uint8_t cod[3];
    uint16_t clock_off;
    uint8_t rssi;
    unsigned char data[240];
};

struct bluetooth_hci_cmd {
    struct {
        unsigned int ogf : 6;  /* opcode group field */
        unsigned int ocf : 10; /* opcode command field */
    } opcode;
    uint8_t param_len; /* parameter total length */
    union {
        uint8_t random_addr[6];
        struct hci_set_extended_scan_params *set_scan;
        struct hci_set_extended_scan_enable *scan_enable;
        struct hci_inquiry *inq;
    } param;
};

struct bluetooth_hci_event {
    uint8_t code;
    uint8_t param_len;
    union {
        uint8_t status;
        struct hci_cmd_complete *cmd;
        struct hci_cmd_status *cstat;
        struct hci_ext_inq_result *res;
        struct hci_le_meta {
            uint8_t subevent_code;
            union {
                struct hci_le_adv_report *rep;
                struct hci_le_ext_adv_report *erep;
            };
        } meta;
    } param;
};

struct bluetooth_hci_info {
    uint32_t direction; /* optional — present for LINKTYPE_BT_HCI_H4_WITH_PHDR */
    uint8_t type;
    union {
        struct bluetooth_hci_cmd *cmd;
        struct bluetooth_hci_event *event;
    };
};

void register_bt_hci(void);

#endif
