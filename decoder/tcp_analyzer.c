#include <stdlib.h>
#include "tcp_analyzer.h"
#include "packet_ip.h"

#define TBLSZ 64 * 1024

static hash_map_t *connection_table = NULL;
static publisher_t *conn_changed_publisher;
static void free_data(void *ptr);

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

void analyzer_init()
{
    connection_table = hash_map_init(TBLSZ, hash_v4, compare_tcp_v4);
    hash_map_set_free_key(connection_table, free);
    hash_map_set_free_data(connection_table, free_data);
    conn_changed_publisher = publisher_init();
}

void analyzer_check_stream(const struct eth_info *ethp)
{
    if (!connection_table) return;

    if (ethp->ethertype == ETH_P_IP) {
        struct tcp *tcp = &ethp->ip->tcp;
        struct packet *p = CONTAINER_OF(ethp, struct packet, eth);
        struct tcp_connection_v4 *conn;
        struct tcp_endpoint_v4 endp;

        endp.src = ethp->ip->src;
        endp.dst = ethp->ip->dst;
        endp.src_port = tcp->src_port;
        endp.dst_port = tcp->dst_port;
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
            publish1(conn_changed_publisher, conn);
        } else if (!tcp->fin) {
            struct tcp_connection_v4 *new_conn;
            struct tcp_endpoint_v4 *new_endp;

            new_endp = malloc(sizeof(struct tcp_endpoint_v4));
            *new_endp = endp;
            new_conn = malloc(sizeof(struct tcp_connection_v4));
            new_conn->endp = new_endp;
            new_conn->packets = list_init();

            list_push_back(new_conn->packets, p);
            if (tcp->syn) {
                new_conn->state = tcp->ack ? SYN_RCVD : SYN_SENT;
            } else { /* already established session */
                new_conn->state = ESTABLISHED;
            }
            hash_map_insert(connection_table, new_endp, new_conn);
            publish1(conn_changed_publisher, new_conn);
        }
    }
}

hash_map_t *analyzer_get_sessions()
{
    return connection_table;
}

void analyzer_subscribe(publisher_fn1 fn)
{
    add_subscription1(conn_changed_publisher, fn);
}

void analyzer_unsubscribe(publisher_fn1 fn)
{
    remove_subscription1(conn_changed_publisher, fn);
}

char *analyzer_get_connection_state(enum connection_state state)
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

void analyzer_clear()
{
    hash_map_clear(connection_table);
}

void analyzer_free()
{
    hash_map_free(connection_table);
    publisher_free(conn_changed_publisher);
    connection_table = NULL;
}

void free_data(void *ptr)
{
    struct tcp_connection_v4 *conn = (struct tcp_connection_v4 *) ptr;

    list_free(conn->packets, NULL);
    free(conn);
}
