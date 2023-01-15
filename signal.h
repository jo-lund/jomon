#ifndef SIGNAL_H
#define SIGNAL_H

typedef struct publisher publisher_t;
typedef void (*publisher_fn0)(void);
typedef void (*publisher_fn1)(void *);
typedef void (*publisher_fn2)(void *, void *);

publisher_t *publisher_init(void);
void publisher_free(publisher_t *p);
void add_subscription0(publisher_t *p, publisher_fn0 f);
void remove_subscription0(publisher_t *p, publisher_fn0 f);
void publish0(publisher_t *p);
void add_subscription1(publisher_t *p, publisher_fn1 f);
void remove_subscription1(publisher_t *p, publisher_fn1 f);
void publish1(publisher_t *p, void *data);
void add_subscription2(publisher_t *p, publisher_fn2 f);
void remove_subscription2(publisher_t *p, publisher_fn2 f);
void publish2(publisher_t *p, void *d1, void *d2);

#endif
