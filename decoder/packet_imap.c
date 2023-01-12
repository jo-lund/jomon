#include <ctype.h>
#include "packet.h"
#include "packet_imap.h"

#define MAXLINE 2048 /* BUG: max line length? */

extern void print_imap(char *buf, int n, void *data);
extern void add_imap_information(void *widget, void *subwidget, void *data);

static struct protocol_info imap_prot = {
    .short_name = "IMAP",
    .long_name = "Internet Message Access Protocol",
    .decode = handle_imap,
    .print_pdu = print_imap,
    .add_pdu = add_imap_information
};

void register_imap()
{
    register_protocol(&imap_prot, PORT, IMAP);
}

packet_error handle_imap(struct protocol_info *pinfo, unsigned char *buf, int n,
                         struct packet_data *pdata)
{
    char line[MAXLINE];
    int i = 0;
    int c = 0;
    struct imap_info *imap;
    bool valid = false;

    imap = mempool_alloc(sizeof(struct imap_info));
    pdata->data = imap;
    pdata->len = n;
    imap->lines = list_init(&d_alloc);
    while (isascii(*buf)) {
        if (c >= MAXLINE) {
            pdata->error = create_error_string("IMAP max line length exceeded (%d)", c);
            return DECODE_ERR;
        }
        if (i >= n) {
            pdata->error = create_error_string("IMAP length greater than packet length (%d)", n);
            return DECODE_ERR;
        }
        if (*buf == '\r') {
            if (++i < n && *++buf == '\n') {
                valid = true;
                list_push_back(imap->lines, mempool_copy0(line, c));
                if (i == n - 1)
                    break;
                i++;
                buf++;
                c = 0;
                continue;
            } else {
                if (i >= n)
                    pdata->error = create_error_string("IMAP length greater than packet length (%d)", n);
                else
                    pdata->error = create_error_string("IMAP EOL error");
                return DECODE_ERR;
            }
        }
        line[c++] = *buf++;
        i++;
    }
    if (valid) {
        pinfo->num_packets++;
        pinfo->num_bytes += n;
        return NO_ERR;
    }
    pdata->error = create_error_string("Not a valid IMAP string");
    return DECODE_ERR;
}
