#include <stdint.h>
#include <stdbool.h>
#include "field.h"
#include "queue.h"
#include "mempool.h"
#include "decoder/packet.h"
#include "string.h"

struct field {
    char *key;
    void *val;
    int type;
    int length;
    QUEUE_ENTRY(struct field) link;
};

void field_init(struct field_head *head)
{
    QUEUE_INIT(head);
}

void field_add_bytes(struct field_head *head, char *key, int type, unsigned char *data, int len)
{
    struct field *f;

    f = mempool_alloc(sizeof(*f));
    f->type = type;
    f->key = key;
    f->val = mempool_copy(data, len);
    f->length = len;
    QUEUE_APPEND(head, f, link);
}

void field_add_value(struct field_head *head, char *key, int type, void *data)
{
    struct field *f;

    f = mempool_alloc(sizeof(*f));
    f->key = key;
    f->type = type;
    switch (type) {
    case FIELD_UINT16:
        f->val = data;
        break;
    case FIELD_UINT_STRING:
        f->val = mempool_copy(data, sizeof(struct uint_string));
        break;
    default:
        break;
    }
    QUEUE_APPEND(head, f, link);
}

bool field_empty(struct field_head *head)
{
    return QUEUE_EMPTY(head);
}

const struct field *field_get_next(struct field_head *head, const struct field *f)
{
    return f ? QUEUE_NEXT(f, link) : head->first;
}

char *field_get_key(const struct field *f)
{
    return f ? f->key : NULL;
}

void *field_get_value(const struct field *f)
{
    return f ? f->val : NULL;
}

int field_get_type(const struct field *f)
{
    return f ? f->type : -1;
}
