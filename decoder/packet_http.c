#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "packet.h"
#include "packet_http.h"

/* It is recommended that all HTTP senders and recipients support, at a minimum,
   request-line lengths of 8000 octets, cf. RFC 7230 */
#define MAX_HTTP_LINE 8000

#define VERSION_LEN 8

enum header_state {
    FIELD,
    VAL,
    EOL
};

static char *request_method[] = {
    "CONNECT",
    "DELETE",
    "GET",
    "HEAD",
    "OPTIONS",
    "POST",
    "PUT",
    "TRACE"
};

#define NUM_METHODS sizeof(request_method) / sizeof(char *)

extern void print_http(char *buf, int n, void *data);
extern void add_http_information(void *widget, void *subwidget, void *data);
static bool parse_http(unsigned char *buf, uint16_t len, struct http_info *http);
static bool parse_start_line(unsigned char **str, unsigned int *len, struct http_info *http);
static bool check_method(char *token);
static bool parse_http_header(unsigned char **str, unsigned int *len, rbtree_t *header);

static struct protocol_info http_prot = {
    .short_name = "HTTP",
    .long_name = "Hypertext Transfer Protocol",
    .port = HTTP,
    .decode = handle_http,
    .print_pdu = print_http,
    .add_pdu = add_http_information
};

void register_http()
{
    register_protocol(&http_prot, LAYER4);
}

static int rbcmp(const void *d1, const void *d2)
{
    return strcmp((char *) d1, (char *) d2);
}

packet_error handle_http(struct protocol_info *pinfo, unsigned char *buffer,
                         int len, void *data)
{
    struct application_info *info = data;

    info->http = mempool_pealloc(sizeof(struct http_info));
    if (!parse_http(buffer, len, info->http)) {
        return UNK_PROTOCOL;
    }
    pinfo->num_packets++;
    pinfo->num_bytes += len;
    return NO_ERR;
}

/*
 * Parses an HTTP string
 *
 * Returns false if there is an error.
 */
bool parse_http(unsigned char *buffer, uint16_t len, struct http_info *http)
{
    unsigned char *ptr;
    bool is_http = false;
    unsigned int n;

    n = len;
    ptr = buffer;
    if (!parse_start_line(&ptr, &n, http)) {
        return false;
    }

    /* parse header fields */
    http->header = rbtree_init(rbcmp, &d_alloc);
    is_http = parse_http_header(&ptr, &n, http->header);

    /* copy message body */
    if (is_http) {
        if (n) {
            http->data = mempool_pecopy(ptr, n);
            http->len = n;
        } else {
            http->len = 0;
        }
    }
    return is_http;
}

bool parse_start_line(unsigned char **str, unsigned int *len, struct http_info *http)
{
    unsigned int i = 0;
    unsigned char *ptr = *str;
    char line[MAX_HTTP_LINE];

    while (isprint(*ptr) && *ptr != ' ') {
        if (i > VERSION_LEN || i > *len) {
            *str = ptr;
            return false;
        }
        line[i++] = *ptr++;
    }
    if (*ptr++ == ' ') {
        line[i] = '\0';
        if (check_method(line) ||
            (*len > VERSION_LEN && strncmp(line, "HTTP/1.1", VERSION_LEN)) == 0) {
            line[i++] = ' ';
            while (isascii(*ptr)) {
                if (i > *len || i > MAX_HTTP_LINE) {
                    *str = ptr;
                    return false;
                }
                if (*ptr == '\r') {
                    if (*++ptr == '\n') {
                        ptr++;
                        http->start_line = mempool_pecopy0(line, i);
                        *len -= (i + 2); /* start_line + CRLF */
                        *str = ptr;
                        return true;
                    } else {
                        *str = ptr;
                        return false;
                    }
                }
                line[i++] = *ptr++;
            }
        }
    }
    *str = ptr;
    return false;
}

bool check_method(char *token)
{
    int low = 0;
    int high = NUM_METHODS - 1;
    int mid;
    int c;

    while (low <= high) {
        mid = (low + high) / 2;
        c = strcmp(token, request_method[mid]);
        if (c == 0) {
            return true;
        } else if (c < 0) {
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    return false;
}

/*
 * Parses the HTTP header and stores the lines containg the field and the value
 * in a list. "len" is a value-result argument and its value is the length of
 * the str argument. On return, the length of the header is subtracted from len
 * (or where it failed in case of error).
 *
 * Returns the result of the operation.
 */
bool parse_http_header(unsigned char **str, unsigned int *len, rbtree_t *header)
{
    int i, j;
    bool eoh = false;
    bool is_http = true;
    unsigned char *ptr = *str;
    char line[MAX_HTTP_LINE];
    int n = *len;
    enum header_state state;

    for (i = 0; i < n && !eoh && is_http; i += j) {
        int c = 0;
        int toklen = 0;

        state = FIELD;
        is_http = false;
        for (j = 0; !is_http && !eoh && isascii(*ptr) && j + i < n; j++, ptr++) {
            if (c > MAX_HTTP_LINE) {
                *len -= (i + j);
                *str = ptr;
                return false;
            }
            switch (state) {
            case FIELD:
                if (*ptr == ':') {
                    state = VAL;
                    toklen = c;
                    line[c++] = *ptr;
                } else if (*ptr == '\r') {
                    state = EOL;
                } else {
                    line[c++] = *ptr;
                }
                break;
            case VAL:
                if (*ptr == '\r') {
                    state = EOL;
                } else {
                    line[c++] = *ptr;
                }
                break;
            case EOL:
                if (*ptr != '\n') {
                    *len -= (i + j);
                    *str = ptr;
                    return false;
                }
                if (j == 1) { /* end of header fields */
                    *len -= (i + j + 1);
                    *str = ptr + 1;
                    return true;
                } else {
                    if (toklen + 1 < c) {
                        char *key = mempool_pecopy0(line, toklen);
                        char *data;

                        while (isblank(line[toklen + 1])) {
                             toklen++;
                        }
                        data = mempool_pecopy0(line + toklen + 1, c - (toklen + 1));
                        rbtree_insert(header, key, data);
                    }
                    is_http = true;
                }
                break;
            }
        }
    }
    *len -= i;
    *str = ptr;
    return false;
}
