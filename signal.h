#ifndef SIGNAL_H
#define SIGNAL_H

typedef struct publisher publisher_t;
typedef void (*publisher_fn0)(void);
typedef void (*publisher_fn1)(void *);
typedef void (*publisher_fn2)(void *, void *);

/* Initialize the publisher. Resources need to be freed by calling publisher_free */
publisher_t *publisher_init(void);

/* Free reources related to publisher */
void publisher_free(publisher_t *p);

/* Add subscription with no arguments */
void add_subscription0(publisher_t *p, publisher_fn0 f);

/* Remove subscription with no arguments */
void remove_subscription0(publisher_t *p, publisher_fn0 f);

/* Invoke subscribers with no arguments */
void publish0(publisher_t *p);

/* Add subscription with 1 argument */
void add_subscription1(publisher_t *p, publisher_fn1 f);

/* Remove subscription with 1 argument */
void remove_subscription1(publisher_t *p, publisher_fn1 f);

/* Invoke subscribers with 1 argument */
void publish1(publisher_t *p, void *data);

/* Add subscription with 2 arguments */
void add_subscription2(publisher_t *p, publisher_fn2 f);

/* Remove subscription with 2 arguments */
void remove_subscription2(publisher_t *p, publisher_fn2 f);

/* Invoke subscribers with 2 arguments */
void publish2(publisher_t *p, void *d1, void *d2);

#endif
