#include <stdlib.h>
#include "signal.h"
#include "list.h"

struct publisher {
    list_t *subscriptions0;
    list_t *subscriptions1;
    list_t *subscriptions2;
};

publisher_t *publisher_init(void)
{
    publisher_t *p = malloc(sizeof(publisher_t));

    p->subscriptions0 = list_init(NULL);
    p->subscriptions1 = list_init(NULL);
    p->subscriptions2 = list_init(NULL);
    return p;
}

void publisher_free(publisher_t *p)
{
    list_free(p->subscriptions0, NULL);
    list_free(p->subscriptions1, NULL);
    list_free(p->subscriptions2, NULL);
    free(p);
}

void add_subscription0(publisher_t *p, publisher_fn0 f)
{
    list_push_back(p->subscriptions0, f);
}

void remove_subscription0(publisher_t *p, publisher_fn0 f)
{
    list_remove(p->subscriptions0, f, NULL);
}

void publish0(publisher_t *p)
{
    const node_t *n = list_begin(p->subscriptions0);

    while (n) {
        publisher_fn0 func = list_data(n);

        if (func) {
            func();
        }
        n = list_next(n);
    }
}

void add_subscription1(publisher_t *p, publisher_fn1 f)
{
    list_push_back(p->subscriptions1, f);
}

void remove_subscription1(publisher_t *p, publisher_fn1 f)
{
    list_remove(p->subscriptions1, f, NULL);
}

void publish1(publisher_t *p, void *d)
{
    const node_t *n = list_begin(p->subscriptions1);

    while (n) {
        publisher_fn1 func = list_data(n);

        if (func) {
            func(d);
        }
        n = list_next(n);
    }
}

void add_subscription2(publisher_t *p, publisher_fn2 f)
{
    list_push_back(p->subscriptions2, f);
}

void remove_subscription2(publisher_t *p, publisher_fn2 f)
{
    list_remove(p->subscriptions2, f, NULL);
}

void publish2(publisher_t *p, void *d1, void *d2)
{
    const node_t *n = list_begin(p->subscriptions2);

    while (n) {
        publisher_fn2 func = list_data(n);

        if (func) {
            func(d1, d2);
        }
        n = list_next(n);
    }
}
