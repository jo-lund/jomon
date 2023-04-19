#ifndef TIMER_H
#define TIMER_H

#include <time.h>
#include <stdbool.h>

/* convert msec to nsec */
#define MS_TO_NS(x) ((x) * 1000000)

typedef void (*timer_cb)(void *);
typedef struct timer mon_timer_t;

/* Create and initialize the timer */
mon_timer_t *timer_init(bool recurring);

/* Arm timer with initial and recurring value based on timespec */
void timer_enable(mon_timer_t *timer, const struct timespec *ts);

/* Disarm timer */
void timer_disable(mon_timer_t *timer);

/* Set callback that should be called when timer expires */
void timer_set_callback(mon_timer_t *timer, timer_cb fn, void *arg);

/* Run pending timers */
void timer_run(void);

/* Free resources */
void timer_free(mon_timer_t *timer);

#endif
