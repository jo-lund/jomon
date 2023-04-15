#ifndef QUEUE_H
#define QUEUE_H

#define QUEUE_HEAD(name, type)  \
    struct name {               \
        type *first;            \
        type **last;            \
    }

#define QUEUE_ENTRY(type)  \
    struct {               \
        type *next;        \
    }

#define QUEUE_INIT(head)               \
    do {                               \
        (head)->first = NULL;          \
        (head)->last = &(head)->first; \
    } while (0)

#define QUEUE_HEAD_INITIALIZER(head) { NULL, &(head).first }

#define QUEUE_NEXT(elem, entry) ((elem)->entry.next)

#define QUEUE_APPEND(head, elem, entry)                     \
    do {                                                    \
        QUEUE_NEXT(elem, entry) = NULL;                     \
        *(head)->last = (elem);                             \
        (head)->last = &QUEUE_NEXT(elem, entry);            \
    } while (0)

#define QUEUE_REMOVE_FIRST(head, entry)                                 \
    do {                                                                \
        if (((head)->first = QUEUE_NEXT((head)->first, entry)) == NULL) \
            (head)->last = &(head)->first;                              \
    } while (0)

#define QUEUE_FOR_EACH(head, elem, entry)                               \
    for ((elem) = (head)->first; (elem); (elem) = QUEUE_NEXT(elem, entry))

#endif
