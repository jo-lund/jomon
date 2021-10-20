#ifndef PROCESS_H
#define PROCESS_H

struct tcp_connection_v4;

/* Initialize process structures */
void process_init(void);

/* Free process structures */
void process_free(void);

/* Reload the process cache */
void process_load_cache(void);

/* Clear the process cache */
void process_clear_cache(void);

/* Get the name of the process that owns the connection */
char *process_get_name(struct tcp_connection_v4 *conn);

#endif
