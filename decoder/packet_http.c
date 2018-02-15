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

static bool parse_http(unsigned char *buf, uint16_t len, struct http_info *http);
static bool parse_start_line(unsigned char **str, unsigned int *len, struct http_info *http);
static bool check_method(char *token);
static bool parse_http_header(unsigned char **str, unsigned int *len, list_t **header);

packet_error handle_http(unsigned char *buffer, uint16_t len, struct application_info *info)
{
    info->http = calloc(1, sizeof(struct http_info));
    if (!parse_http(buffer, len, info->http)) {
        return UNK_PROTOCOL;
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
    bool is_http = false;
    unsigned int n;

    n = len;
    ptr = buffer;
    if (!parse_start_line(&ptr, &n, http)) {
        return false;
    }

    /* parse header fields */
    http->header = list_init();
    is_http = parse_http_header(&ptr, &n, &http->header);

    /* copy message body */
    if (is_http) {
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
                        line[i] = '\0';
                        http->start_line = strdup(line);
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
bool parse_http_header(unsigned char **str, unsigned int *len, list_t **header)
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
                    line[c] = '\0';
                    list_push_back(*header, strdup(line));
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
