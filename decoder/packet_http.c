#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "packet.h"
#include "packet_http.h"

#define MAX_HTTP_LINE 4096

static enum http_state {
    FIELD,
    VAL,
    EOL
} state;

static bool parse_http(unsigned char *buf, uint16_t len, struct http_info *http);
static bool parse_http_header(unsigned char **str, unsigned int *len, list_t **header);

packet_error handle_http(unsigned char *buffer, uint16_t len, struct application_info *info)
{
    info->http = malloc(sizeof(struct http_info));
    if (!parse_http(buffer, len, info->http)) {
        return HTTP_ERR;
    }
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
    char line[MAX_HTTP_LINE];
    bool is_http = false;
    int i;
    int n;

    i = 0;
    n = len;
    ptr = buffer;

    /* parse start line */
    while (isascii(*ptr)) {
        if (i > len || i > MAX_HTTP_LINE) return false;
        if (*ptr == '\r') {
            if (*++ptr == '\n') {
                ptr++;
                is_http = true;
                break;
            } else {
                return false;
            }
        }
        line[i++] = *ptr++;
    }
    if (!is_http) return false;
    line[i] = '\0';
    http->start_line = strdup(line);

    /* parse header fields */
    unsigned int header_len;

    http->header = list_init();
    n -= (i + 2); /* subtract i + CRLF */
    header_len = n;
    is_http = parse_http_header(&ptr, &header_len, &http->header);

    /* copy message body */
    if (is_http) {
        n -= header_len;
        if (n) {
            http->data = malloc(n);
            memcpy(http->data, ptr, n);
            http->len = n;
        }
        pstat[PROT_HTTP].num_packets++;
        pstat[PROT_HTTP].num_bytes += len;
    }
    return is_http;
}

/*
 * Parses the HTTP header and stores the lines containg the field and the value
 * in a list. "len" is a value-result argument and its value is the length of
 * the str argument. On return, the length of the header is stored in len (or
 * where it failed in case of error).
 *
 * Returns the result of the operation.
 */
bool parse_http_header(unsigned char **str, unsigned int *len, list_t **header)
{
    int i, j;
    bool eoh = false;
    bool is_http = true;
    unsigned char *ptr = *str;
    char line[MAX_HTTP_LINE];
    int n = *len;

    for (i = 0; i < n && !eoh && is_http; i += j) {
        int c = 0;

        state = FIELD;
        is_http = false;
        for (j = 0; !is_http && !eoh && isascii(*ptr) && j + i < n; j++, ptr++) {
            if (c > MAX_HTTP_LINE) {
                *len = i + j;
                *str = ptr;
                return false;
            }
            switch (state) {
            case FIELD:
                if (*ptr == ':') {
                    state = VAL;
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
                    *len = i + j;
                    *str = ptr;
                    return false;
                }
                if (j == 1) { /* end of header fields */
                    *len = i + j + 1;
                    *str = ptr + 1;
                    return true;
                } else {
                    line[c] = '\0';
                    list_push_back(*header, strdup(line));
                    is_http = true;
                }
                break;
            }
        }
    }
    *len = i;
    *str = ptr;
    return false;
}

void free_http_packet(struct http_info *http)
{
    if (http) {
        if (http->start_line) {
            free(http->start_line);
        }
        if (http->header) {
            list_free(http->header, free);
        }
        if (http->data) {
            free(http->data);
        }
        free(http);
    }
}
