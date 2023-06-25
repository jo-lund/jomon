#ifndef TCP_ANALYZER_H
#define TCP_ANALYZER_H

#include "packet_ethernet.h"
#include "hashmap.h"
#include "signal.h"
#include "list.h"
#include "queue.h"

enum connection_state {
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
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
    QUEUE_HEAD(, struct packet) packets;
    uint32_t size;
    uint32_t num;
    void *data; /* Protocol related meta-data. Can be NULL */
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

/* Initialize the TCP analyzer */
void tcp_analyzer_init(void);

/* Analyze the packet and if TCP store the connection in a table */
void tcp_analyzer_check_stream(struct packet *p);

/* Return the connection table */
hashmap_t *tcp_analyzer_get_sessions(void);

/* Return the connection based on the given endpoint, or NULL if not found */
struct tcp_connection_v4 *tcp_analyzer_get_connection(struct tcp_endpoint_v4 *endp);

/* Create a new connection based on the given endpoint */
struct tcp_connection_v4 *tcp_analyzer_create_connection(struct tcp_endpoint_v4 *endp);

/* Remove a connection */
void tcp_analyzer_remove_connection(struct tcp_endpoint_v4 *endp);

/* Subscribe to connection changes, e.g. more data or state changes */
void tcp_analyzer_subscribe(analyzer_conn_fn fn);

/* Unsubscribe to TCP connection changes */
void tcp_analyzer_unsubscribe(analyzer_conn_fn fn);

/* Return the connection state */
char *tcp_analyzer_get_connection_state(enum connection_state);

/* Clear the connection table */
void tcp_analyzer_clear(void);

/* Free all structures related to the TCP connections */
void tcp_analyzer_free(void);

#endif
