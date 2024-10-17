#ifndef PORTABILITY_H
#define PORTABILITY_H

#if defined(MACOS) || defined(__FreeBSD__)
struct bsdarg {
    int (*compar)(const void *, const void *, void *);
    void *thunk;
};

static inline int cmpbsd(void *arg, const void *p1, const void *p2)
{
    struct bsdarg *t = (struct bsdarg *) arg;
    return t->compar(p1, p2, t->thunk);
}

#define QSORT(base, nmemb, size, cmp, arg)      \
    struct bsdarg thunk = {                     \
        .compar = (cmp),                        \
        .thunk = (arg)                          \
    };                                          \
    qsort_r(base, nmemb, size, &thunk, cmpbsd)
#else
#define QSORT(base, nmemb, size, cmp, arg) \
    qsort_r(base, nmemb, size, cmp, arg)
#endif

#endif
