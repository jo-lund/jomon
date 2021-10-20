#include <stdlib.h>
#include <ctype.h>
#include "packet.h"
#include "packet_smtp.h"
#include "packet_imap.h"
#include "../monitor.h"
#include "tcp_analyzer.h"
#include "packet_ip.h"
#include "packet_tls.h"

/*
 * The maximum total length of a text line including the <CRLF> is 1000 octets
 * (not counting the leading dot duplicated for transparency). This number may
 * be increased by the use of SMTP Service Extensions.
 */
#define MAXLENGTH 2048
#define REPLY_CODE_DIGITS 3

extern void print_smtp(char *buf, int n, void *data);
extern void add_smtp_information(void *widget, void *subwidget, void *data);
static packet_error handle_smtp(struct protocol_info *pinfo, unsigned char *buf, int n,
                                struct packet_data *pdata);

/*
 * There are four values for the first digit of the reply code (see RFC 5321):
 * 2yz  Positive Completion reply
 * 3yz  Positive Intermediate reply
 * 4yz  Transient Negative Completion reply
 * 5yz  Permanent Negative Completion reply
 *
 * The second digit encodes responses in specific categories:
 * x0z  Syntax: These replies refer to syntax errors
 * x1z  Information: These are replies to requests for information, such
 *      as status or help.
 * x2z  Connections: These are replies referring to the transmission channel
 * x3z  Unspecified.
 * x4z  Unspecified.
 * x5z  Mail system: These replies indicate the status of the receiver
 *      mail system vis-a-vis the requested transfer or other mail system
 *      action.
 *
 * The third digit gives a finer gradation of meaning in each category
 * specified by the second digit.
 */
static struct uint_string reply_codes[] = {
  { 211, "System status, or system help reply" },
  { 214, "Help message" },
  { 220, "<domain> Service ready" },
  { 221, "<domain> Service closing transmission channel" },
  { 235, "Authentication successful" },
  { 250, "Requested mail action okay, completed" },
  { 251, "User not local; will forward to <forward-path>" },
  { 252, "Cannot VRFY user, but will accept message and attempt delivery" },
  { 334, "AUTH input" },
  { 354, "Start mail input; end with <CRLF>.<CRLF>" },
  { 421, "<domain> Service not available, closing transmission channel" },
  { 432, "A password transition is needed" },
  { 450, "Requested mail action not taken: mailbox unavailable" },
  { 451, "Requested action aborted: local error in processing" },
  { 452, "Requested action not taken: insufficient system storage" },
  { 454, "Temporary authenticaion failed" },
  { 500, "Syntax error, command unrecognized" },
  { 501, "Syntax error in parameters or arguments" },
  { 502, "Command not implemented" },
  { 503, "Bad sequence of commands" },
  { 504, "Command parameter not implemented" },
  { 530, "Authentication required" },
  { 534, "Authentication mechanism is too weak" },
  { 535, "Authentication credentials invalid" },
  { 538, "Encryption required for requested authentication mechanism" },
  { 550, "Requested action not taken: mailbox unavailable" },
  { 551, "User not local; please try <forward-path>" },
  { 552, "Requested mail action aborted: exceeded storage allocation" },
  { 553, "Requested action not taken: mailbox name not allowed" },
  { 554, "Transaction failed" },
};

enum smtp_state {
    NORMAL,
    WAIT_DATA,
    DATA,
    WAIT_TLS,
    TLS
};

struct smtp_conn_state {
    enum smtp_state state;
    int chunk_size; /* BDAT chunk size */
    bool last_chunk;
};

static struct protocol_info smtp_prot = {
    .short_name = "SMTP",
    .long_name = "Simple Mail Transfer Protocol",
    .decode = handle_smtp,
    .print_pdu = print_smtp,
    .add_pdu = add_smtp_information
};

void register_smtp(void)
{
    register_protocol(&smtp_prot, PORT, SMTP);
    register_protocol(&smtp_prot, PORT, SMTP_EMS);
    register_protocol(&smtp_prot, PORT, SMTP_ALT);
}

static int cmp_code(const void *c1, const void *c2)
{
    struct uint_string *code1 = (struct uint_string *) c1;
    struct uint_string *code2 = (struct uint_string *) c2;

    return code1->val - code2->val;
}

static bool parse_line(struct smtp_info *smtp, char *buf, int n, int *i)
{
    int c;
    char *p;

    p = buf + *i;
    if (smtp->response) {
        while (isdigit(*p)) {
            p++;
            ++*i;
        }
        if (*p == '-') {
            p++;
            ++*i;
        }
    }
    while (*p == ' ') {
        p++;
        ++*i;
    }
    c = *i;
    while (isascii(*p) && *i < n) {
        if (*p == '\r') {
            if (*++p == '\n') {
                *i += 2;
                if (smtp->response)
                    list_push_back(smtp->rsp.lines, mempool_copy0(buf + c, *i - c - 2));
                else
                    smtp->cmd.params = mempool_copy0(buf + c, *i - c - 2);
                return true;
            } else {
                return false;
            }
        }
        p++;
        ++*i;
    }
    return false;
}

static struct packet_data *get_root(struct packet_data *pdata)
{
    struct packet_data *p = pdata;

    while (p->prev)
        p = p->prev;
    return p;
}

static packet_error handle_smtp(struct protocol_info *pinfo, unsigned char *buf, int n,
                                struct packet_data *pdata)
{
    struct smtp_info *smtp;
    unsigned char *p;
    int i = 0;
    struct smtp_conn_state *smtp_state;
    struct packet_data *root;
    struct tcp *tcp;
    struct tcp_endpoint_v4 endp;
    struct ipv4_info *ipv4;
    struct tcp_connection_v4 *conn;

     /* only support for TCP and IPv4 */
    if (pdata->transport != TCP)
        return DECODE_ERR;
    root = get_root(pdata);
    if (!root || (root && root->id != get_protocol_id(ETHERNET_II, ETHERTYPE_IP)))
        return DECODE_ERR;
    if (!root->next && !root->next->next)
        return DECODE_ERR;

    ipv4 = root->next->data;
    tcp = root->next->next->data;
    endp.sport = tcp->sport;
    endp.dport = tcp->dport;
    endp.src = ipv4->src;
    endp.dst = ipv4->dst;
    if ((conn = tcp_analyzer_get_connection(&endp)) == NULL) {
        conn = tcp_analyzer_create_connection(&endp);
        conn->state = ESTABLISHED;
    }
    if (!conn->data) {
        smtp_state = mempool_alloc(sizeof(*smtp_state));
        smtp_state->state = NORMAL;
        conn->data = smtp_state;
    } else {
        smtp_state = conn->data;
    }
    if (smtp_state->state == TLS) {
        pdata->prev->id = get_protocol_id(PORT, SMTPS);
        pinfo = get_protocol(pdata->prev->id);
        return pinfo->decode(pinfo, buf, n, pdata);
    }
    p = buf;
    smtp = mempool_alloc(sizeof(struct smtp_info));
    smtp->data = NULL;
    pdata->data = smtp;
    pdata->len = n;
    if (smtp_state->state == DATA) {
        smtp->data = mempool_copy(buf, n);
        smtp->len = n;
        if (strncmp(smtp->data, "\r\n.\r\n", 5) == 0)
            smtp_state->state = NORMAL;
        goto ok;
    }
    if (isdigit(*p)) {
        if (n < REPLY_CODE_DIGITS)
            goto error;
        smtp->response = true;
        smtp->rsp.lines = list_init(&d_alloc);
        smtp->rsp.code = 0;
        while (isdigit(*p) && i < REPLY_CODE_DIGITS) {
            smtp->rsp.code = 10 * smtp->rsp.code + (*p++ - '0');
            i++;
        }
        if (isdigit(*p))
            goto error;
        switch (smtp_state->state) {
        case WAIT_DATA:
            if (smtp->rsp.code == 354)
                smtp_state->state = DATA;
            break;
        case WAIT_TLS:
            if (smtp->rsp.code == 220)
                smtp_state->state = TLS;
            break;
        default:
            break;
        }
    } else {
        char line[MAXLENGTH];

        smtp->response = false;
        while (isprint(*p) && *p != ' ' && i < n) {
            if (i >= MAXLENGTH)
                goto error;
            line[i++] = *p++;
        }
        /* TODO: Check to see if valid command */
        smtp->cmd.command = mempool_copy0(line, i);
        if (strncmp(smtp->cmd.command, "DATA", 4) == 0)
            smtp_state->state = WAIT_DATA;
        else if (strncmp(smtp->cmd.command, "STARTTLS", 8) == 0)
            smtp_state->state = WAIT_TLS;
    }
    if (i < n && (*p == ' ' || *p == '-')) {
        int j = 0;

        while (i < n) {
            if (!parse_line(smtp, (char *) buf, n, &i))
                goto error;
            if (j == 0)
                smtp->start_line = mempool_copy0(buf, i - 2);
            j++;
        }
    } else if (!smtp->response) {
        smtp->start_line = smtp->cmd.command;
        smtp->cmd.command = NULL;
    } else {
        goto error;
    }
ok:
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    return NO_ERR;

error:
    mempool_free(smtp);
    return DECODE_ERR;
}

char *get_smtp_code(int code)
{
    struct uint_string *res;
    struct uint_string key;

    key.val = code;
    res = bsearch(&key, reply_codes, ARRAY_SIZE(reply_codes), sizeof(struct uint_string), cmp_code);
    if (res)
        return res->str;
    return NULL;
}
