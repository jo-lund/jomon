#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "packet_ethernet.h"
#include "packet_stp.h"
#include "packet.h"
#include "packet_llc.h"
#include "util.h"
#include "field.h"
#include "string.h"

#define MIN_CONF_BPDU 35
#define MIN_BPDU_LEN 4

enum stp_bpdu_type {
    CONFIG = 0x0,
    RST = 0x2,
    TCN = 0x80
};

static void print_stp(char *buf, int n, struct packet_data *pdata);
static packet_error handle_stp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                               struct packet_data *pdata);

static char *set[] = { "No", "Yes" };

static struct packet_flags stp_flags[] = {
    { "Topology Change Acknowledgement", 1, set },
    { "Agreement", 1, set },
    { "Forwarding", 1, set },
    { "Learning", 1, set },
    { "Port Role", 2, (char *[]) { "Unused", "Alternate/Backup", "Root", "Designated" } },
    { "Proposal", 1, set },
    { "Topology Change", 1, set }
};

static struct protocol_info stp = {
    .short_name = "STP",
    .long_name = "Spanning Tree Protocol",
    .decode = handle_stp,
    .print_pdu = print_stp,
};

void register_stp(void)
{
    register_protocol(&stp, ETH802_3, ETH_802_STP);
    register_protocol(&stp, ETH802_3, 0x010b);
}

static char *get_stp_bpdu_type(uint8_t type)
{
    switch (type) {
    case CONFIG:
        return "Configuration BPDU";
    case RST:
        return "Rapid Spanning Tree BPDU";
    case TCN:
        return "Topology Change Notification BPDU";
    default:
        return "Unknown";
    }
}

/*
 * IEEE 802.1 Bridge Spanning Tree Protocol
 */
packet_error handle_stp(struct protocol_info *pinfo, unsigned char *buf, int n,
                        struct packet_data *pdata)
{
    uint16_t protocol_id;
    struct uint_string type;
    uint8_t flags;

    /* the BPDU shall contain at least 4 bytes */
    if (n < MIN_BPDU_LEN) {
        pdata->error = create_error_string("Packet length (%d) less than minimum BPDU size (4)", n);
        return DECODE_ERR;
    }
    field_init(&pdata->data);
    protocol_id = read_uint16be(&buf);
    field_add_value(&pdata->data, "Protocol Id", FIELD_UINT16, UINT_TO_PTR(protocol_id));

    /* protocol id 0x00 identifies the (Rapid) Spanning Tree Protocol */
    if (protocol_id != 0x0) {
        pdata->error = create_error_string("Unknown protocol id (%d)", protocol_id);
        return UNK_PROTOCOL;
    }
    field_add_value(&pdata->data, "Version", FIELD_UINT8, UINT_TO_PTR(buf[0]));
    buf++;
    type.val = buf[0];
    type.str = get_stp_bpdu_type(type.val);
    field_add_value(&pdata->data, "Type", FIELD_UINT_STRING, &type);
    buf++;

    /* a configuration BPDU contains at least 35 bytes and RST BPDU 36 bytes */
    if (n >= MIN_CONF_BPDU && (type.val == CONFIG || type.val == RST)) {
        flags = buf[0];
        field_add_bitfield(&pdata->data, "Flags", flags, false, &stp_flags, ARRAY_SIZE(stp_flags));
        buf++;
        field_add_bytes(&pdata->data, "Root ID", FIELD_UINT16_HWADDR, buf, 8);
        buf += 8;
        field_add_value(&pdata->data, "Root path cost", FIELD_UINT32, UINT_TO_PTR(read_uint32be(&buf)));
        field_add_bytes(&pdata->data, "Bridge ID", FIELD_UINT16_HWADDR, buf, 8);
        buf += 8;
        field_add_value(&pdata->data, "Port ID", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(&pdata->data, "Message age", FIELD_TIME_UINT16_256, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(&pdata->data, "Max age", FIELD_TIME_UINT16_256, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(&pdata->data, "Hello time", FIELD_TIME_UINT16_256, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(&pdata->data, "Forward delay", FIELD_TIME_UINT16_256, UINT_TO_PTR(read_uint16be(&buf)));
        if (n > MIN_CONF_BPDU && type.val == RST)
            field_add_value(&pdata->data, "Version 1 Length", FIELD_UINT8, UINT_TO_PTR(buf[0]));
    }
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    return NO_ERR;
}

void print_stp(char *buf, int n, struct packet_data *pdata)
{
    struct uint_string *type;
    uint32_t root_pc;
    uint16_t port_id;
    const struct field *f;

    type = field_search_value(&pdata->data, "Type");
    switch (type->val) {
    case CONFIG:
        f = field_search(&pdata->data, "Root path cost");
        root_pc = field_get_uint32(f);
        f = field_search(&pdata->data, "Port ID");
        port_id = field_get_uint16(f);
        snprintf(buf, n, "Configuration BPDU. Root Path Cost: %u  Port ID: 0x%x",
                 root_pc, port_id);
        break;
    case RST:
        f = field_search(&pdata->data, "Root path cost");
        root_pc = field_get_uint32(f);
        f = field_search(&pdata->data, "Port ID");
        port_id = field_get_uint16(f);
        snprintf(buf, n, "Rapid Spanning Tree BPDU. Root Path Cost: %u  Port ID: 0x%x",
                   root_pc, port_id);
        break;
    case TCN:
        snprintf(buf, n, "Topology Change Notification BPDU");
        break;
    }
}
