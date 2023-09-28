#include <stdio.h>
#include "string.h"
#include "print_protocol.h"
#include "util.h"
#include "interface.h"
#include "decoder/packet.h"
#include "decoder/packet_ethernet.h"

static void print_unknown(char *buf, int size, struct packet *p)
{
    char smac[HW_ADDRSTRLEN];
    char dmac[HW_ADDRSTRLEN];
    char time[TBUFLEN];
    struct packet_data *pdata;

    pdata = p->root;
    switch (get_protocol_key(pdata->id)) {
    case LINKTYPE_ETHERNET:
        if (eth_len(p) <= 0)
            return;
        HW_ADDR_NTOP(smac, eth_src(p));
        HW_ADDR_NTOP(dmac, eth_dst(p));
        format_timeval(&p->time, time, TBUFLEN);
        PRINT_LINE(buf, size, p->num, time, smac, dmac, "ETH II", "Ethertype: 0x%x",
                   ethertype(p));
        break;
    case LINKTYPE_BT_HCI_H4_WITH_PHDR:
        break;
    default:
        break;
    }
}

void pkt2text(char *buf, size_t size, struct packet *p)
{
    struct protocol_info *pinfo;

    pinfo = (p->root->next) ? get_protocol(p->root->next->id) : get_protocol(p->root->id);
    if (pinfo) {
        char time[TBUFLEN];
        struct timeval t = p->time;

        format_timeval(&t, time, TBUFLEN);
        PRINT_NUMBER(buf, size, p->num);
        PRINT_TIME(buf, size, time);
        if (p->root->next && p->root->next->data)
            pinfo->print_pdu(buf, size, p->root->next);
        else if (p->root->data)
            pinfo->print_pdu(buf, size, p->root);
    } else {
        print_unknown(buf, size, p);
    }
}
