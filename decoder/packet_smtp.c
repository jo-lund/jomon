#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "packet.h"
#include "packet_smtp.h"
#include "packet_imap.h"
#include "../jomon.h"
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
    TLS,
    BDAT
};

struct smtp_conn_state {
    enum smtp_state state;
    int chunk_size; /* BDAT chunk size */
    bool last_chunk;
};

struct smtp_data {
    struct smtp_cmd *cmd;
    struct smtp_rsp *rsp;
};

static struct protocol_info smtp_prot = {
    .short_name = "SMTP",
    .long_name = "Simple Mail Transfer Protocol",
    .decode = handle_smtp,
    .print_pdu = print_smtp,
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

static bool parse_line(struct smtp_info *smtp, struct smtp_data *data, char *buf, int n, int *i)
{
    int c;
    char *p;

    if (*i >= n)
        return false;
    p = buf + *i;
    while (*p == ' ') {
        p++;
        if (++*i >= n)
            return false;
    }
    c = *i;
    while (*i < n && isascii(*p)) {
        if (*p == '\r') {
            if (*i + 2 > n)
                return false;
            if (*++p == '\n') {
                *i += 2;
                if (smtp->response)
                    list_push_back(data->rsp->lines, mempool_copy0(buf + c, *i - c - 2));
                else
                    data->cmd->params = mempool_copy0(buf + c, *i - c - 2);
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
    struct tcp_connection_v4 *conn;
    bool conn_created = false;

     /* only support for TCP and IPv4 */
#if 0 // TODO: Fix this
    if (pdata->transport != IPPROTO_TCP)
        return UNK_PROTOCOL;
    if ((root = get_root(pdata)) == NULL)
        return UNK_PROTOCOL;
    if ((!root->next || root->next->id != get_protocol_id(ETHERNET_II, ETHERTYPE_IP)) ||
        !root->next->next)
        return UNK_PROTOCOL;

    ipv4 = root->next->data;
    tcp = root->next->next->data;
    endp.sport = tcp->sport;
    endp.dport = tcp->dport;
    endp.src = ipv4->src;
    endp.dst = ipv4->dst;
#endif
    if ((conn = tcp_analyzer_get_connection(&endp)) == NULL) {
        conn = tcp_analyzer_create_connection(&endp);
        conn->state = ESTABLISHED;
        conn_created = true;
    }
    if (!conn->data) {
        smtp_state = mempool_calloc(1, struct smtp_conn_state);
        smtp_state->state = NORMAL;
        conn->data = smtp_state;
    } else {
        smtp_state = conn->data;
    }
    if (smtp_state->state == TLS) {
        pdata->id = get_protocol_id(PORT, SMTPS);
        pinfo = get_protocol(pdata->id);
        return pinfo->decode(pinfo, buf, n, pdata);
    }
    p = buf;
    smtp = mempool_calloc(1, struct smtp_info);
    smtp->data = NULL;
    pdata->len = n;
    if (smtp_state->state == DATA || smtp_state->state == BDAT) {
        smtp->data = (char *) buf;
        smtp->len = n;
        if (smtp_state->state == DATA && n >= 5 &&
            strncmp(smtp->data + n - 5, "\r\n.\r\n", 5) == 0) {
            smtp_state->state = NORMAL;
        } else if (smtp_state->state == BDAT) {
            smtp_state->chunk_size -= n;
            if (smtp_state->chunk_size <= 0)
                smtp_state->state = NORMAL;
        }
        goto ok;
    }
    if (isdigit(*p)) { /* response */
        if (n < REPLY_CODE_DIGITS) {
            pdata->error = create_error_string("Packet length too short (%d)", n);
            goto error;
        }
        struct smtp_data data;
        struct smtp_rsp *rsp;

        smtp->response = true;
        smtp->rsps = list_init(&d_alloc);
        while (i < n) {
            int j = 0;
            bool last_line = false;

            rsp = mempool_alloc(sizeof(*rsp));
            rsp->lines = list_init(&d_alloc);
            rsp->code = 0;
            while (isdigit(*p) && j++ < REPLY_CODE_DIGITS) {
                rsp->code = 10 * rsp->code + (*p++ - '0');
                if (++i >= n) {
                    pdata->error = create_error_string("Packet length too short (%d)", n);
                    goto error;
                }
            }
            if (isdigit(*p)) {
                pdata->error = create_error_string("Too many digits in reply code");
                goto error;
            }
            switch (smtp_state->state) {
            case WAIT_DATA:
                if (rsp->code == 354)
                    smtp_state->state = DATA;
                break;
            case WAIT_TLS:
                if (rsp->code == 220)
                    smtp_state->state = TLS;
                break;
            default:
                break;
            }
            while (i < n && !last_line) {
                while (isdigit(*p)) {
                    if (++i >= n) {
                        pdata->error = create_error_string("Error parsing SMTP line");
                        goto error;
                    }
                    p++;
                }
                if (*p == '-') {
                    p++;
                    i++;
                } else if (*p == ' ') {
                    last_line = true;
                    p++;
                    i++;
                }
                data.rsp = rsp;
                if (!parse_line(smtp, &data, (char *) buf, n, &i)) {
                    pdata->error = create_error_string("Error parsing SMTP line");
                    goto error;
                }
                p = buf + i;
            }
            list_push_back(smtp->rsps, rsp);
        }
    } else { /* command */
        struct smtp_data data;
        struct smtp_cmd *cmd;

        smtp->response = false;
        smtp->cmds = list_init(&d_alloc);
        while (i < n) {
            if (smtp_state->state == BDAT) {
                int len = n - i;

                smtp->data = mempool_copy(buf, n);
                smtp->len = n;
                smtp_state->chunk_size -= len;
                if (smtp_state->chunk_size <= 0)
                    smtp_state->state = NORMAL;
                goto ok;
            }
            int j = 0;
            unsigned char *s = p;

            while (i < n && isprint(*p) && *p != ' ') {
                if (i++ >= MAXLENGTH) {
                    pdata->error = create_error_string("Line too long (%d)", i);
                    goto error;
                }
                p++;
                j++;
            }
            if (i >= n) {
                pdata->error = create_error_string("SMTP line greater than packet data length (%d)", n);
                goto error;
            }
            cmd = mempool_alloc(sizeof(*cmd));
            cmd->command = mempool_copy0(s, j);
            data.cmd = cmd;
            if (!parse_line(smtp, &data, (char *) buf, n, &i)) {
                pdata->error = create_error_string("Error parsing SMTP line");
                goto error;
            }
            p = buf + i;
            list_push_back(smtp->cmds, cmd);
            if (strcmp(cmd->command, "DATA") == 0)
                smtp_state->state = WAIT_DATA;
            else if (strcmp(cmd->command, "STARTTLS") == 0)
                smtp_state->state = WAIT_TLS;
            else if (strcmp(cmd->command, "BDAT") == 0) {
                char *s;

                smtp_state->state = BDAT;
                errno = 0;
                smtp_state->chunk_size = strtol(cmd->params, &s, 10);
                if (errno != 0 || (smtp_state->chunk_size == 0 && *cmd->params == *s)) {
                    pdata->error = create_error_string("BDAT command parameter error");
                    goto error;
                }
                while (*s == ' ') {
                    if (++s >= (char *) p) {
                        pdata->error = create_error_string("Too many spaces in command argument");
                        goto error;
                    }
                }
                if (strcmp(s, "LAST") == 0)
                    smtp_state->last_chunk = true;
                if (smtp_state->last_chunk && smtp_state->chunk_size == 0)
                    smtp_state->state = NORMAL;
            }
        }
    }
ok:
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    return NO_ERR;

error:
    if (conn_created)
        tcp_analyzer_remove_connection(&endp);
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
