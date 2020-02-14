#ifndef PROCESS_H
#define PROCESS_H

struct tcp_connection_v4;

void process_init();
void process_free();
void process_load_cache();
void process_clear_cache();
char *process_get_name(struct tcp_connection_v4 *conn);

#endif
