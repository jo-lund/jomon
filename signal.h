#ifndef SIGNAL_H
#define SIGNAL_H

typedef struct publisher publisher_t;
typedef void (*function)(void);

publisher_t *publisher_init();
void publisher_free(publisher_t *p);
void add_subscription(publisher_t *p, function f);
void remove_subscription(publisher_t *p, function f);
void publish(publisher_t *p);

#endif
