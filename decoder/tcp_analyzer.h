#ifndef TCP_ANALYZER_H
#define TCP_ANALYZER_H

#include "packet_ethernet.h"
#include "../hashmap.h"
#include "../signal.h"

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
};

void analyzer_init();
void analyzer_check_stream(const struct eth_info *eth);
hash_map_t *analyzer_get_sessions();
void analyzer_subscribe(publisher_fn1 fn);
void analyzer_unsubscribe(publisher_fn1 fn);
char *analyzer_get_connection_state(enum connection_state);
void analyzer_clear();
void analyzer_free();

#endif
