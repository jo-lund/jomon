#include <ctype.h>
#include "packet.h"
#include "packet_imap.h"

#define MAXLINE 2048 /* BUG: max line length? */

extern void print_imap(char *buf, int n, void *data);
extern void add_imap_information(void *widget, void *subwidget, void *data);

static struct protocol_info imap_prot = {
    .short_name = "IMAP",
    .long_name = "Internet Message Access Prorocol",
    .decode = handle_imap,
    .print_pdu = print_imap,
    .add_pdu = add_imap_information
};

void register_imap()
{
    register_protocol(&imap_prot, LAYER4, IMAP);
}

packet_error handle_imap(struct protocol_info *pinfo, unsigned char *buf, int n,
                         struct packet_data *pdata)
{
    char line[MAXLINE];
    int i = 0;
    int c = 0;
    struct imap_info *imap;

    imap = mempool_pealloc(sizeof(struct imap_info));
    pdata->data = imap;
    pdata->len = n;
    imap->lines = list_init(&d_alloc);
    while (isascii(*buf)) {
        if (c >= MAXLINE || i >= n) return IMAP_ERR;
        if (*buf == '\r') {
            if (++i < n && *++buf == '\n') {
                list_push_back(imap->lines, mempool_pecopy0(line, c));
                if (i == n - 1) break;
                i++;
                buf++;
                c = 0;
                continue;
            } else {
                return IMAP_ERR;
            }
        }
        line[c++] = *buf++;
        i++;
    }
    if (i > 1) {
        pinfo->num_packets++;
        pinfo->num_bytes += n;
        return NO_ERR;
    }
    mempool_pefree(imap->lines);
    imap->lines = NULL;
    return IMAP_ERR;
}
