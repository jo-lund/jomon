#ifndef SIGNAL_H
#define SIGNAL_H

typedef void (*function)(void);

void init_publisher();
void add_subscription(function f);
void remove_subscription(function f);
void publish();

#endif
