#include <string.h>
#include <signal.h>
#include <stdint.h>
#include "timer.h"
#include "wrapper.h"
#include "queue.h"
#include "util.h"

struct timer {
    timer_t t;
    bool recurring;
    timer_cb cb;
    void *arg;
    QUEUE_ENTRY(struct timer) link;
};

struct tqueue {
    QUEUE_HEAD(, struct timer) head;
    size_t len;
};

struct tqueue pending = { QUEUE_HEAD_INITIALIZER(pending.head), 0 };

static void sig_timer(int sig UNUSED, siginfo_t *info, void *ucontext UNUSED)
{
    mon_timer_t *t;

    QUEUE_FOR_EACH(&pending.head, t, link) {
        if (t == info->si_ptr)
            return;
    }
    QUEUE_APPEND(&pending.head, (mon_timer_t *) info->si_ptr, link);
}

mon_timer_t *timer_init(bool recurring)
{
    struct sigevent sigev;
    mon_timer_t *timer;

    memset(&sigev, 0, sizeof(sigev));
    timer = xcalloc(1, sizeof(*timer));
    timer->recurring = recurring;
    timer->link.next = NULL;
    sigev.sigev_value.sival_ptr = timer;
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = SIGRTMIN;
    if (timer_create(CLOCK_REALTIME, &sigev, &timer->t) < 0)
        err_sys("timer_create error");
    setup_sigaction(SIGRTMIN, sig_timer, 0);
    return timer;
}

void timer_enable(mon_timer_t *timer, const struct timespec *ts)
{
    struct itimerspec it;

    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec = ts->tv_sec;
    it.it_value.tv_nsec = ts->tv_nsec;
    if (timer->recurring) {
        it.it_interval.tv_sec = ts->tv_sec;
        it.it_interval.tv_nsec = ts->tv_nsec;
    }
    if (timer_settime(timer->t, 0, &it, NULL) < 0)
        err_sys("timer_settime error");
}

void timer_disable(mon_timer_t *timer)
{
    struct itimerspec it;

    memset(&it, 0, sizeof(it));
    if (timer_settime(timer->t, 0, &it, NULL) < 0)
        err_sys("timer_settime error");
}

void timer_set_callback(mon_timer_t *timer, timer_cb fn, void *arg)
{
    timer->cb = fn;
    timer->arg = arg;
}

void timer_run(void)
{
    mon_timer_t *t;

    QUEUE_FOR_EACH(&pending.head, t, link) {
        if (t->cb)
            t->cb(t->arg);
        QUEUE_REMOVE_FIRST(&pending.head, link);
    }
}

void timer_free(mon_timer_t *timer)
{
    timer_delete(timer->t);
    free(timer);
}
