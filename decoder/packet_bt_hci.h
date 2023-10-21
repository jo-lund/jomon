#ifndef PACKET_BT
#define PACKET_BT

#include <stdint.h>
#include <stddef.h>

#define LAPSTR "%02x:%02x:%02x"
#define LAP2STR(x) (x)[0], (x)[1], (x)[2]

#define BT_EXT_SCAN_PARAMS_DURATION(x) ((x) * 0.625)
#define BT_EXT_SCAN_ENABLE_DURATION(x) ((x) * 10)
#define BT_EXT_SCAN_ENABLE_PERIOD(x) ((x) * 1.28)

#define BT_HCI_COMMAND 1
#define BT_HCI_ACL_DATA 2
#define BT_HCI_SYNC_DATA 3
#define BT_HCI_EVENT 4
#define BT_HCI_ISO_DATA 5

/*
 * The Link Control commands allow a Controller to control connections to other
 * BR/EDR Controllers.
 */
#define BT_LINK_CTRL_CMD (0x1 << 10)
#define   BT_HCI_INQUIRY 0x0001
#define   BT_HCI_INQUIRY_CANCEL 0x0002
#define   BT_HCI_PERIODIC_INQUIRY_MODE 0x0003
#define   BT_HCI_EXIT_PERIODIC_INQUIRY_MODE 0x0004
#define   BT_HCI_CREATE_CONNECTION 0x0005
#define   BT_HCI_DISCONNECT 0x0006
#define   BT_HCI_CREATE_CONNECTION_CANCEL 0x0008
#define   BT_HCI_ACCEPT_CONN_REQ 0x0009
#define   BT_HCO_REJECT_CONN_REQ 0x000a
#define   BT_HCI_LINK_KEY_REQ_REPLY 0x000b
#define   BT_HCI_LINK_KEY_REQ_NEG_REPLY 0x000c
#define   BT_HCI_PIN_CODE_REQ_REPLY 0x000d
#define   BT_HCI_PIN_CODE_REQ_NEG_REPLY 0x000e
#define   BT_HCI_CHANGE_CONN_PKT_TYPE 0x000f
#define   BT_HCI_AUTH_REQUESTED 0x0011
#define   BT_HCI_SET_CONN_ENCRYPTION 0x0013
#define   BT_HCI_CHANGE_CONN_LINK_KEY 0x0015
#define   BT_HCI_LINK_KEY_SELECTION 0x0017

/*
 * The Link Policy commands provide methods for the Host to affect how the Link
 * Manager manages the piconet.
 */
#define BT_LINK_POLICY_CMD (0x2 << 10)
#define   BT_HCI_HOLD_MODE 0x0001
#define   BT_HCI_SNIFF_MODE 0x0003
#define   BT_HCI_EXIT_SNIFF_MODE 0x0004
#define   BT_HCI_QOS_SETUP 0x0007
#define   BT_HCI_ROLE_DISC 0x0009
#define   BT_HCI_SWITCH_ROLE 0x000b
#define   BT_HCI_READ_LINK_POL_SET 0x000c
#define   BT_HCI_WRITE_LINK_POL_SET 0x000d
#define   BT_HCI_READ_DEF_LINK_POL_SET 0x000e
#define   BT_HCI_WRITE_DEF_LINK_POL_SET 0x000f
#define   BT_HCI_FLOW_SPEC 0x0010
#define   BT_HCI_SNIFF_SUBRAT 0x0011

/*
 * The Controller & Baseband commands provide access and control to various
 * capabilities of the Bluetooth hardware
 */
#define BT_CTRL_BB_CMD (0x3 << 10)
#define   BT_HCI_SET_EVENT_MASK 0x0001
#define   BT_HCI_RESET 0x0003
#define   BT_HCI_SET_EVENT_FILTER 0x0005
#define   BT_HCI_FLUSH 0x0008
#define   BT_HCI_READ_PIN_TYPE 0x0009
#define   BT_HCI_WRITE_PIN_TYPE 0x000a
#define   BT_HCI_READ_STORED_LINK_KEY 0x000d
#define   BT_HCI_WRITE_STORED_LINK_KEY 0x0011
#define   BT_HCI_DELETE_STORED_LINK_KEY 0x0012
#define   BT_HCI_WRITE_LOC_NAME 0x0013
#define   BT_HCI_READ_LOC_NAME 0x0014
#define   BT_HCI_READ_CONN_ACCEPT_TIMEOUT 0x0015
#define   BT_HCI_WRITE_CONN_ACCEPT_TIMEOUT 0x0016
#define   BT_HCI_READ_PAGE_TIMEOUT 0x0017
#define   BT_HCI_WRITE_PAGE_TIMEOUT 0x0018
#define   BT_HCI_READ_SCAN_ENABLE 0x0019
#define   BT_HCI_WRITE_SCAN_ENABLE 0x001a
#define   BT_HCI_READ_PAGE_SCAN_ACTIVITY 0x001b
#define   BT_HCI_WRITE_PAGE_SCAN_ACTIVITY 0x001c
#define   BT_HCI_READ_INQ_SCAN_ACTIVITY 0x001d
#define   BT_HCI_WRITE_INQ_SCAN_ACTIVITY 0x001e
#define   BT_HCI_READ_AUTH_ENABLE 0x001f
#define   BT_HCI_WRITE_AUTH_ENABLE 0x0020
#define   BT_HCI_READ_ENC_MODE 0x0021   /* deprecated */
#define   BT_HCI_WRITE_ENC_MODE 0x0022  /* deprecated */
#define   BT_HCI_READ_COD 0X0023
#define   BT_HCI_WRITE_COD 0x0024
#define   BT_HCI_READ_VOICE_SETTING 0x0024
#define   BT_HCI_WRITE_VOICE_SETTING 0X0025

/*
 * The informational parameters are fixed by the manufacturer of the Bluetooth
 * hardware.
 */
#define BT_INF_PARAMS (0x4 << 10)
#define   BT_HCI_READ_LOC_VERINF 0x1
#define   BT_HCI_READ_LOC_SUP_CMDS 0x2
#define   BT_HCI_READ_LOC_SUP_FEATURES 0x3
#define   BT_HCI_READ_LOC_EXT_FEATURES 0x4
#define   BT_HCI_READ_BUF_SIZE 0x5
#define   BT_HCI_READ_BD_ADDR 0x9
#define   BT_HCI_READ_DATA_BLOCK_SIZE 0xa
#define   BT_HCI_READ_LOC_SUP_CODECS_V1 0xb
#define   BT_HCI_READ_LOC_SUP_CODECS_V2 0xd
#define   BT_HCI_READ_LOC_SIMPLE_PAIRING_OPTS 0xc
#define   BT_HCI_READ_LOC_SUP_CODECS_CAP 0xe
#define   BT_HCI_READ_LOC_SUP_CTRL_DELAY 0xf

/*
 * The Controller modifies all status parameters. These parameters provide
 * information about the current state of the Link Manager and Baseband in the
 * BR/EDR Controller.
 */
#define BT_STATUS_PARAMS (0x5 << 10)

/*
 * The Testing commands are used to provide the ability to test various functional
 * capabilities of the Bluetooth hardware.
 */
#define BT_TESTING_CMD (0x6 << 10)

/*
 * The LE Controller commands provide access and control to various capabilities
 * of the Bluetooth hardware, as well as methods for the Host to affect how the
 * Link Layer manages the piconet and controls connections
 */
#define BT_LE_CTRL_CMD (0x8 << 10)
#define   BT_HCI_LE_SET_EVENT_MASK 0x000
#define   BT_HCI_LE_READ_BUFFER_SIZE_V1 0x0002
#define   BT_HCI_LE_READ_BUFFER_SIZE_V2 0x0060
#define   BT_HCI_LE_READ_LOC_SUPPORTED_FEATURES 0x0003
#define   BT_HCI_LE_SET_RANDOM_ADDR 0x0005
#define   BT_HCI_LE_SET_ADV_PARAMS 0x0006
#define   BT_HCI_LE_SET_EXTENDED_SCAN_PARAMS 0x0041
#define   BT_HCI_LE_SET_EXTENDED_SCAN_ENABLE 0x0042

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
    BT_HCI_CONNECTION_COMPLETE = 0x3,
    BT_HCI_CONNECTION_REQUEST = 0x4,
    BT_HCI_DISCONNECTION_COMPLETE = 0x5,
    BT_HCI_AUTH_COMPLETE = 0x6,
    BT_HCI_REMOTE_NAME_REQ_COMPLETE = 0x7,
    BT_HCI_ENCRYPTION_CHANGE = 0x8,
    BT_HCI_CHANGE_CONN_LINK_KEY_COMPLETE = 0x9,
    BT_HCI_MASTER_LINK_KEY_COMPLETE = 0xa,
    BT_HCI_READ_REM_SUP_FEAT_COMPLETE = 0xb,
    BT_HCI_READ_REM_VER_INF_COMPLETE = 0xc,
    BT_HCI_QOS_SETUP_COMPLETE = 0xd,
    BT_HCI_CMD_COMPLETE = 0xe,
    BT_HCI_CMD_STATUS = 0xf,
    BT_HCI_HW_ERR = 0x10,
    BT_HCI_FLUSH_OCCURRED = 0x11,
    BT_HCI_ROLE_CHANGE = 0x12,
    BT_HCI_NUM_COMPLETE_PKTS = 0x13,
    BT_HCI_MODE_CHANGE = 0x14,
    BT_HCI_RETURN_LINK_KEYS = 0x15,
    BT_HCI_PIN_CODE_REQ = 0x16,
    BT_HCI_LINK_KEY_REQ = 0x17,
    BT_HCI_LINK_KEY_NOTIFICATION = 0x18,
    BT_HCI_LOOPBACK_CMD = 0x19,
    BT_HCI_DATA_BUF_OVERFLOW = 0x1a,
    BT_HCI_MAX_SLOTS_CHANGE = 0x1b,
    BT_HCI_READ_CLK_OFF_COMPLETE = 0x1c,
    BT_HCI_CONN_PKT_TYPE_CHANGED = 0x1d,
    BT_HCI_QOS_VIOLATION = 0x1e,
    BT_HCI_PAGE_SCAN_REP_MODE_CHANGE = 0x20,
    BT_HCI_FLOW_SPEC_COMPLETE = 0x21,
    BT_HCI_INQ_RES_RSSI = 0x22,
    BT_HCI_READ_REM_EXT_FEAT_COMPLETE = 0x23,
    BT_HCI_SYNC_CONN_COMPLETE = 0X2c,
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
    BT_HCI_LE_EXT_ADV_REPORT,
    BT_HCI_LE_PER_ADV_SYNC_EST
};

/* LE Controller commands */
struct hci_set_extended_scan_params {
    uint8_t own_address_type;
    uint8_t scanning_filter_policy;
    uint8_t scanning_phy;
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

/* Link Control commands */
struct hci_inquiry {
    uint8_t lap[3];
    uint8_t inquiry_len;
    uint8_t nresp;
};

/* Controller & Baseband commands */
struct hci_enc_mode {
    uint8_t status;
    uint8_t mode;
};

struct hci_loc_sup_features {
    uint8_t status;
    uint64_t lmp_features;
};

/* Events */
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

#define GET_OGF(x) ((x) & 0xfc00)
#define GET_OCF(x) ((x) & 0x3ff)

struct bluetooth_hci_cmd {
    uint16_t opcode;
    uint8_t param_len; /* parameter total length */
    union {
        uint8_t random_addr[6];
        struct hci_set_extended_scan_params *set_scan;
        struct hci_set_extended_scan_enable *scan_enable;
        struct hci_inquiry *inq;
        struct hci_loc_sup_features *feat;
        struct hci_enc_mode *mode;
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
char *bt2string(char *buf, size_t n, struct bluetooth_hci_info *info);
struct packet_flags *get_bt_opcode_flags(void);
int get_bt_opcode_flags_size(void);
struct packet_flags *get_bt_scanning_phy_flags(void);
int get_bt_scanning_phy_flags_size(void);
char *get_bt_type(uint8_t type);
char *get_bt_command(uint16_t opcode);
char *get_bt_event_code(uint8_t code);
char *get_bt_error_string(uint8_t error_code);
char *get_bt_oat(uint8_t type);
char *get_bt_scanning_filter_policy(uint8_t filter);
char *get_bt_scan_type(uint8_t type);
char *get_bt_filter_dup(uint8_t type);

#endif
