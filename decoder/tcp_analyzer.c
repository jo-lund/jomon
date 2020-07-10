#include <stdlib.h>
#include "tcp_analyzer.h"
#include "packet_ip.h"

#define TBLSZ 64 * 1024

static hashmap_t *connection_table = NULL;
static publisher_t *conn_changed_publisher;

void tcp_analyzer_init()
{
    connection_table = hashmap_init(TBLSZ, hash_tcp_v4, compare_tcp_v4);
    conn_changed_publisher = publisher_init();
}

void tcp_analyzer_check_stream(const struct packet *p)
{
    if (!connection_table)
        return;

    struct packet_data *pdata;

    if (ethertype(p) == ETH_P_IP &&
        (pdata = get_packet_data(p, get_protocol_id(IP_PROTOCOL, IPPROTO_TCP)))) {
        struct tcp *tcp = pdata->data;
        struct tcp_connection_v4 *conn;
        struct tcp_endpoint_v4 endp;

        endp.src = ipv4_src(p);
        endp.dst = ipv4_dst(p);
        endp.sport = tcp_member(p, src_port);
        endp.dport = tcp_member(p, dst_port);
        conn = hashmap_get(connection_table, &endp);
        if (conn) {
            list_push_back(conn->packets, (struct packet *) p);
            if (tcp->rst) {
                conn->state = RESET;
            }
            switch (conn->state) {
            case SYN_SENT:
                if (tcp->syn && tcp->ack) {
                    conn->state = SYN_RCVD;
                }
                break;
            case SYN_RCVD:
                if (tcp->ack) {
                    conn->state = ESTABLISHED;
                }
                break;
            case ESTABLISHED:
                if (tcp->fin) {
                    conn->state = tcp->ack ? CLOSING : CLOSE_WAIT;
                }
                break;
            case CLOSE_WAIT:
                if (tcp->fin) {
                    conn->state = CLOSING;
                }
                break;
            case CLOSING:
                if (tcp->ack) {
                    conn->state = CLOSED;
                }
            default:
                break;
            }
            publish2(conn_changed_publisher, conn, NULL);
        } else if (!tcp->fin) {
            struct tcp_connection_v4 *new_conn;
            struct tcp_endpoint_v4 *new_endp;

            new_endp = mempool_pecopy(&endp, sizeof(struct tcp_endpoint_v4));
            new_conn = mempool_pealloc(sizeof(struct tcp_connection_v4));
            new_conn->endp = new_endp;
            new_conn->packets = list_init(&d_alloc);
            list_push_back(new_conn->packets, (void *) p);
            if (tcp->syn) {
                new_conn->state = tcp->ack ? SYN_RCVD : SYN_SENT;
            } else { /* already established session */
                new_conn->state = ESTABLISHED;
            }
            hashmap_insert(connection_table, new_endp, new_conn);
            publish2(conn_changed_publisher, new_conn, (void *) 0x1);
        }
    }
}

hashmap_t *tcp_analyzer_get_sessions()
{
    return connection_table;
}

void tcp_analyzer_subscribe(analyzer_conn_fn fn)
{
    if (conn_changed_publisher)
        add_subscription2(conn_changed_publisher, (publisher_fn2) fn);
}

void tcp_analyzer_unsubscribe(analyzer_conn_fn fn)
{
    if (conn_changed_publisher)
        remove_subscription2(conn_changed_publisher, (publisher_fn2) fn);
}

char *tcp_analyzer_get_connection_state(enum connection_state state)
{
    switch (state) {
    case SYN_SENT:
    case SYN_RCVD:
        return "Initializing";
    case ESTABLISHED:
        return "Established";
    case CLOSE_WAIT:
    case CLOSING:
        return "Closing";
    case RESET:
        return "Reset";
    case CLOSED:
        return "Closed";
    default:
        return "";
    }
}

void tcp_analyzer_clear()
{
    if (connection_table)
        hashmap_clear(connection_table);
}

void tcp_analyzer_free()
{
    hashmap_free(connection_table);
    publisher_free(conn_changed_publisher);
    connection_table = NULL;
    conn_changed_publisher = NULL;
}
