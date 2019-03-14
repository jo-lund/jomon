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
    uint32_t src;
    uint32_t dst;
    uint16_t src_port;
    uint16_t dst_port;
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

void tcp_analyzer_init();
void tcp_analyzer_check_stream(const struct packet *p);
hash_map_t *tcp_analyzer_get_sessions();
void tcp_analyzer_subscribe(analyzer_conn_fn fn);
void tcp_analyzer_unsubscribe(analyzer_conn_fn fn);
char *tcp_analyzer_get_connection_state(enum connection_state);
void tcp_analyzer_clear();
void tcp_analyzer_free();

#endif
