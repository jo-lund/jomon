#include <stdlib.h>
#include "tcp_analyzer.h"
#include "packet_ip.h"

#define TBLSZ 64 * 1024

static hash_map_t *connection_table = NULL;
static publisher_t *conn_changed_publisher;

static unsigned int hash_v4(const void *key)
{
    struct tcp_endpoint_v4 *endp = (struct tcp_endpoint_v4 *) key;
    unsigned int hash = 2166136261;
    unsigned int val = endp->src + endp->dst + endp->src_port + endp->dst_port;

    for (int i = 0; i < 4; i++) {
        hash = (hash ^ ((val >> (8 * i)) & 0xff)) * 16777619;
    }
    return hash;
}

static int compare_tcp_v4(const void *t1, const void *t2)
{
    struct tcp_endpoint_v4 *endp1 = (struct tcp_endpoint_v4 *) t1;
    struct tcp_endpoint_v4 *endp2 = (struct tcp_endpoint_v4 *) t2;

    if ((endp1->src == endp2->src && endp1->dst == endp2->dst &&
         endp1->src_port == endp2->src_port && endp1->dst_port == endp2->dst_port)
        || (endp1->src == endp2->dst && endp1->src_port == endp2->dst_port &&
            endp1->dst == endp2->src && endp1->dst_port == endp2->src_port)) {
        return 0;
    }
    return (endp1->src + endp1->dst + endp1->src_port + endp1->dst_port) -
        (endp2->src + endp2->dst + endp2->src_port + endp2->dst_port);
}

void tcp_analyzer_init()
{
    connection_table = hash_map_init(TBLSZ, hash_v4, compare_tcp_v4);
    conn_changed_publisher = publisher_init();
}

void tcp_analyzer_check_stream(const struct packet *p)
{
    if (!connection_table) return;

    if (p->eth.ethertype == ETH_P_IP) {
        struct tcp *tcp = &p->eth.ip->tcp;
        struct tcp_connection_v4 *conn;
        struct tcp_endpoint_v4 endp;

        endp.src = ipv4_src(p);
        endp.dst = ipv4_dst(p);
        endp.src_port = tcpv4_src(p);
        endp.dst_port = tcpv4_dst(p);
        conn = hash_map_get(connection_table, &endp);
        if (conn) {
            list_push_back(conn->packets, p);
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
            list_push_back(new_conn->packets, p);
            if (tcp->syn) {
                new_conn->state = tcp->ack ? SYN_RCVD : SYN_SENT;
            } else { /* already established session */
                new_conn->state = ESTABLISHED;
            }
            hash_map_insert(connection_table, new_endp, new_conn);
            publish2(conn_changed_publisher, new_conn, (void *) 0x1);
        }
    }
}

hash_map_t *tcp_analyzer_get_sessions()
{
    return connection_table;
}

void tcp_analyzer_subscribe(analyzer_conn_fn fn)
{
    add_subscription2(conn_changed_publisher, (publisher_fn2) fn);
}

void tcp_analyzer_unsubscribe(analyzer_conn_fn fn)
{
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
    hash_map_clear(connection_table);
}

void tcp_analyzer_free()
{
    hash_map_free(connection_table);
    publisher_free(conn_changed_publisher);
    connection_table = NULL;
}
