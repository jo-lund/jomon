#include <string.h>
#include "packet_ssdp.h"
#include "packet.h"
#include "../list.h"

extern void print_ssdp(char *buf, int n, void *data);
extern void add_ssdp_information(void *widget, void *subwidget, void *data);
static packet_error parse_ssdp(struct packet_data *pdata, char *str, int n,
                               list_t *msg_header);

static struct protocol_info ssdp_prot = {
    .short_name = "SSDP",
    .long_name = "Simple Service Discovery Protocol",
    .decode = handle_ssdp,
    .print_pdu = print_ssdp,
    .add_pdu = add_ssdp_information
};

void register_ssdp(void)
{
    register_protocol(&ssdp_prot, PORT, SSDP);
}

/*
 * The Simple Service Discovery Protocol (SSDP) is a network protocol based on
 * the Internet Protocol Suite for advertisement and discovery of network
 * services and presence information. It is a text-based protocol based on HTTP.
 * Services are announced by the hosting system with multicast addressing to a
 * specifically designated IP multicast address at UDP port number 1900.
 *
 * SSDP uses a NOTIFY HTTP method to announce the establishment or withdrawal of
 * services (presence) information to the multicast group. A client that wishes
 * to discover available services on a network uses the M-SEARCH method.
 * Responses to such search requests are sent via unicast addressing to the
 * originating address and port number of the multicast request.
 */
packet_error handle_ssdp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    struct ssdp_info *ssdp;

    ssdp = mempool_alloc(sizeof(struct ssdp_info));
    pdata->data = ssdp;
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    ssdp->fields = list_init(&d_alloc);
    return parse_ssdp(pdata, (char *) buffer, n, ssdp->fields);
}

/*
 * Parses an SSDP string. SSDP strings are based on HTTP1.1 but contains no
 * message body.
 *
 * Copies the lines delimited by CRLF, i.e. the start line and the SSDP message
 * header fields, to msg_header list.
 *
 * TODO: Use HTTP parser
 */
packet_error parse_ssdp(struct packet_data *pdata, char *str, int n, list_t *msg_header)
{
    char *token;
    char cstr[n + 1];
    size_t len = 0;

    strncpy(cstr, str, n);
    cstr[n] = '\0';
    token = strtok(cstr, "\r\n");
    len += 2;
    while (token) {
        char *field;
        size_t toklen;

        toklen = strlen(token);
        len += toklen + 2;
        field = mempool_copy0(token, toklen);
        list_push_back(msg_header, field);
        token = strtok(NULL, "\r\n");
    }
    if ((size_t) n != len) {
        pdata->error = create_error_string("SSDP length (%lu) != packet data length (%d)", len, n);
        return DECODE_ERR;
    }
    return NO_ERR;
}
