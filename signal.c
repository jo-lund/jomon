#include <stdlib.h>
#include "signal.h"
#include "list.h"

static list_t *subscriptions;

void init_publisher()
{
    subscriptions = list_init();
}

void add_subscription(function f)
{
    list_push_back(subscriptions, f);
}

void remove_subscription(function f)
{
    list_remove(subscriptions, f, NULL);
}

void publish()
{
    const node_t *n = list_begin(subscriptions);

    while (n) {
        function func = list_data(n);

        if (func) {
            func();
        }
        n = list_next(n);
    }
}
