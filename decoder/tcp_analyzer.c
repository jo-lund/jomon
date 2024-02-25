#include <stdlib.h>
#include "tcp_analyzer.h"
#include "packet_ip.h"

#define TBLSZ (64 * 1024)

static hashmap_t *connection_table = NULL;
static publisher_t *conn_changed_publisher;
static int nconnections = 0;

void tcp_analyzer_init(void)
{
    connection_table = hashmap_init(TBLSZ, hash_tcp_v4, compare_tcp_v4);
    conn_changed_publisher = publisher_init();
}

void tcp_analyzer_check_stream(struct packet *p)
{
    if (!connection_table)
        return;

    struct packet_data *pdata;

    if (ethertype(p) == ETHERTYPE_IP &&
        (pdata = get_packet_data(p, get_protocol_id(IP_PROT, IPPROTO_TCP)))) {
        if (pdata->error)
            return;

        struct tcp *tcp = pdata->data;
        struct tcp_connection_v4 *conn;
        struct tcp_endpoint_v4 endp;

        endp.src = ipv4_src(p);
        endp.dst = ipv4_dst(p);
        endp.sport = tcp_member(p, sport);
        endp.dport = tcp_member(p, dport);
        conn = hashmap_get(connection_table, &endp);
        if (conn) {
            bool is_new = QUEUE_EMPTY(&conn->packets);

            QUEUE_APPEND(&conn->packets, p, link);
            conn->size++;
            if (tcp->rst)
                conn->state = RESET;
            switch (conn->state) {
            case SYN_SENT:
                if (tcp->syn && tcp->ack)
                    conn->state = SYN_RCVD;
                break;
            case SYN_RCVD:
                if (tcp->ack)
                    conn->state = ESTABLISHED;
                break;
            case ESTABLISHED:
                if (tcp->fin)
                    conn->state = CLOSING;
                break;
            case CLOSING:
                if (tcp->fin)
                    conn->state = CLOSED;
            default:
                break;
            }
            publish2(conn_changed_publisher, conn, is_new ? (void *) 0x1 : NULL);
        } else {
            struct tcp_connection_v4 *new_conn = tcp_analyzer_create_connection(&endp);

            if (tcp->syn)
                new_conn->state = tcp->ack ? SYN_RCVD : SYN_SENT;
            else if (tcp->rst)
                new_conn->state = RESET;
            else if (tcp->fin)
                new_conn->state = CLOSING;
            else /* already established session */
                new_conn->state = ESTABLISHED;
            QUEUE_APPEND(&new_conn->packets, p, link);
            new_conn->size++;
            publish2(conn_changed_publisher, new_conn, (void *) 0x1);
        }
    }
}

struct tcp_connection_v4 *tcp_analyzer_create_connection(struct tcp_endpoint_v4 *endp)
{
    struct tcp_connection_v4 *new_conn;
    struct tcp_endpoint_v4 *new_endp;

    new_endp = mempool_copy(endp, sizeof(struct tcp_endpoint_v4));
    new_conn = mempool_alloc(sizeof(struct tcp_connection_v4));
    new_conn->endp = new_endp;
    QUEUE_INIT(&new_conn->packets);
    new_conn->size = 0;
    new_conn->num = nconnections++;
    new_conn->data = NULL;
    hashmap_insert(connection_table, new_endp, new_conn);
    return new_conn;
}

struct tcp_connection_v4 *tcp_analyzer_get_connection(struct tcp_endpoint_v4 *endp)
{
    if (connection_table)
        return hashmap_get(connection_table, endp);
    return NULL;
}

void tcp_analyzer_remove_connection(struct tcp_endpoint_v4 *endp)
{
    if (connection_table)
        hashmap_remove(connection_table, endp);
}

hashmap_t *tcp_analyzer_get_sessions(void)
{
    return connection_table;
}

void tcp_analyzer_subscribe(analyzer_conn_fn fn)
{
    if (conn_changed_publisher)
        add_subscription2(conn_changed_publisher, (publisher_fn2) (void *) fn);
}

void tcp_analyzer_unsubscribe(analyzer_conn_fn fn)
{
    if (conn_changed_publisher)
        remove_subscription2(conn_changed_publisher, (publisher_fn2) (void *) fn);
}

char *tcp_analyzer_get_connection_state(enum connection_state state)
{
    switch (state) {
    case SYN_SENT:
    case SYN_RCVD:
        return "Initializing";
    case ESTABLISHED:
        return "Established";
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

void tcp_analyzer_clear(void)
{
    if (connection_table)
        hashmap_clear(connection_table);
    nconnections = 0;
}

void tcp_analyzer_free(void)
{
    if (connection_table) {
        hashmap_free(connection_table);
        publisher_free(conn_changed_publisher);
        connection_table = NULL;
        conn_changed_publisher = NULL;
    }
}
