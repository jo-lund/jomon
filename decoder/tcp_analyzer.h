#ifndef TCP_ANALYZER_H
#define TCP_ANALYZER_H

#include "packet_ethernet.h"
#include "../hashmap.h"
#include "../signal.h"
#include "../list.h"

enum connection_state {
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    CLOSE_WAIT,
    CLOSING,
    RESET,
    CLOSED
};

struct tcp_endpoint_v4 {
    uint16_t sport;
    uint16_t dport;
    uint32_t src; /* stored in network byte order */
    uint32_t dst; /* stored in network byte order */
};

struct tcp_connection_v4 {
    struct tcp_endpoint_v4 *endp;
    enum connection_state state;
    list_t *packets;
};

/*
 * Function that will be called on new and updated connections. The second
 * argument specifies whether the connection is new or not.
 */
typedef void (*analyzer_conn_fn)(struct tcp_connection_v4 *, bool);

static inline unsigned int hash_tcp_v4(const void *key)
{
    struct tcp_endpoint_v4 *endp = (struct tcp_endpoint_v4 *) key;
    unsigned int hash = 2166136261;
    unsigned int val = endp->src + endp->dst + endp->sport + endp->dport;

    for (int i = 0; i < 4; i++) {
        hash = (hash ^ ((val >> (8 * i)) & 0xff)) * 16777619;
    }
    return hash;
}

static inline int compare_tcp_v4(const void *t1, const void *t2)
{
    struct tcp_endpoint_v4 *endp1 = (struct tcp_endpoint_v4 *) t1;
    struct tcp_endpoint_v4 *endp2 = (struct tcp_endpoint_v4 *) t2;

    if ((endp1->src == endp2->src && endp1->dst == endp2->dst &&
         endp1->sport == endp2->sport && endp1->dport == endp2->dport)
        || (endp1->src == endp2->dst && endp1->sport == endp2->dport &&
            endp1->dst == endp2->src && endp1->dport == endp2->sport)) {
        return 0;
    }
    return (endp1->src + endp1->dst + endp1->sport + endp1->dport) -
        (endp2->src + endp2->dst + endp2->sport + endp2->dport);
}

void tcp_analyzer_init();
void tcp_analyzer_check_stream(const struct packet *p);
hashmap_t *tcp_analyzer_get_sessions();
void tcp_analyzer_subscribe(analyzer_conn_fn fn);
void tcp_analyzer_unsubscribe(analyzer_conn_fn fn);
char *tcp_analyzer_get_connection_state(enum connection_state);
void tcp_analyzer_clear();
void tcp_analyzer_free();

#endif
