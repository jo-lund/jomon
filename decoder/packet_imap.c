#include <ctype.h>
#include "packet.h"
#include "packet_imap.h"

#define MAXLINE 2048 /* BUG: max line length? */

packet_error handle_imap(unsigned char *buf, int n, struct application_info *adu)
{
    char line[MAXLINE];
    int i = 0;
    int c = 0;

    adu->imap = mempool_pealloc(sizeof(struct imap_info));
    adu->imap->lines = list_init(mempool_pealloc);
    while (isascii(*buf)) {
        if (c >= MAXLINE || i >= n) return IMAP_ERR;
        if (*buf == '\r') {
            if (++i < n && *++buf == '\n') {
                list_push_back(adu->imap->lines, mempool_pecopy0(line, c));
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
        pstat[PROT_IMAP].num_packets++;
        pstat[PROT_IMAP].num_bytes += n;
        return NO_ERR;
    }
    mempool_pefree(adu->imap->lines);
    adu->imap->lines = NULL;
    return IMAP_ERR;
}
