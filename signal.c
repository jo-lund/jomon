#include <stdlib.h>
#include "signal.h"
#include "list.h"

struct publisher {
    list_t *subscriptions;
};

publisher_t *publisher_init()
{
    publisher_t *p = malloc(sizeof(publisher_t));

    p->subscriptions = list_init();
    return p;
}

void publisher_free(publisher_t *p)
{
    list_free(p->subscriptions, NULL);
    free(p);
}

void add_subscription(publisher_t *p, function f)
{
    list_push_back(p->subscriptions, f);
}

void remove_subscription(publisher_t *p, function f)
{
    list_remove(p->subscriptions, f, NULL);
}

void publish(publisher_t *p)
{
    const node_t *n = list_begin(p->subscriptions);

    while (n) {
        function func = list_data(n);

        if (func) {
            func();
        }
        n = list_next(n);
    }
}
