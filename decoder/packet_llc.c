#include <string.h>
#include <stdio.h>
#include "packet_llc.h"
#include "field.h"
#include "util.h"

static void print_llc(char *buf, int n, struct packet_data *data);
static packet_error handle_llc(struct protocol_info *pinfo, unsigned char *buf, int n,
                               struct packet_data *pdata);

static struct protocol_info llc = {
    .short_name = "LLC",
    .long_name = "Logical Link Control",
    .decode = handle_llc,
    .print_info = print_llc,
};

void register_llc(void)
{
    register_protocol(&llc, ETH802_3, ETH_802_LLC);
}

packet_error handle_llc(struct protocol_info *pinfo, unsigned char *buf, int n, struct packet_data *pdata)
{
    struct protocol_info *psub;
    uint32_t id;

    if (n < LLC_HDR_LEN) {
        pdata->error = create_error_string("Packet length (%d) less than LLC header (%d)", n, LLC_HDR_LEN);
        return DECODE_ERR;
    }
    field_init(&pdata->data2);
    field_add_value(&pdata->data2, "Destination Service Access Point (DSAP)", FIELD_UINT8,
                    UINT_TO_PTR(buf[0]));
    field_add_value(&pdata->data2, "Source Service Access Point (SSAP)", FIELD_UINT8,
                    UINT_TO_PTR(buf[1]));
    field_add_value(&pdata->data2, "Control", FIELD_UINT8, UINT_TO_PTR(buf[2]));
    pdata->len = LLC_HDR_LEN;
    pinfo->num_packets++;
    pinfo->num_bytes += LLC_HDR_LEN;
    id = get_protocol_id(ETH802_3, (buf[0] << 8) | buf[1]);
    if ((buf[0] << 8 | buf[1]) == 0xffff) /* invalid id */
        return UNK_PROTOCOL;
    if ((psub = get_protocol(id))) {
        pdata->next = mempool_calloc(1, struct packet_data);
        pdata->next->id = id;
        return psub->decode(psub, buf + LLC_HDR_LEN, n - LLC_HDR_LEN, pdata->next);
    }
    return UNK_PROTOCOL;
}

static void print_llc(char *buf, int n, struct packet_data *pdata)
{
    const struct field *f;
    uint8_t ssap, dsap, control;

    f = field_search(&pdata->data2, "Destination Service Access Point (DSAP)");
    dsap = field_get_uint8(f);
    f = field_search(&pdata->data2, "Source Service Access Point (SSAP)");
    ssap = field_get_uint8(f);
    f = field_search(&pdata->data2, "Control");
    control = field_get_uint8(f);
    snprintf(buf, n, "SSAP: 0x%x  DSAP: 0x%x  Control: 0x%x", ssap, dsap, control);
}
