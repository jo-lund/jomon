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

void analyzer_init();
void analyzer_check_stream(const struct eth_info *eth);
hash_map_t *analyzer_get_sessions();
void analyzer_subscribe(analyzer_conn_fn fn);
void analyzer_unsubscribe(analyzer_conn_fn fn);
char *analyzer_get_connection_state(enum connection_state);
void analyzer_clear();
void analyzer_free();

#endif
