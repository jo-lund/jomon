#ifndef SIGNAL_H
#define SIGNAL_H

typedef struct publisher publisher_t;
typedef void (*publisher_fn0)();
typedef void (*publisher_fn1)(void *);

publisher_t *publisher_init();
void publisher_free(publisher_t *p);
void add_subscription0(publisher_t *p, publisher_fn0 f);
void remove_subscription0(publisher_t *p, publisher_fn0 f);
void publish0(publisher_t *p);
void add_subscription1(publisher_t *p, publisher_fn1 f);
void remove_subscription1(publisher_t *p, publisher_fn1 f);
void publish1(publisher_t *p, void *data);

#endif
