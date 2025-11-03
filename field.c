#include <stdint.h>
#include <stdbool.h>
#include "field.h"
#include "queue.h"
#include "mempool.h"
#include "decoder/packet.h"
#include "string.h"
#include "util.h"

struct field {
    char *key;
    void *val;
    uint16_t type;
    uint16_t flags;
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
    f->flags = 0;
    QUEUE_APPEND(head, f, link);
}

void field_add_value(struct field_head *head, char *key, int type, void *data)
{
    struct field *f;

    f = mempool_alloc(sizeof(*f));
    f->key = key;
    f->type = type;
    f->flags = 0;
    switch (type) {
    case FIELD_UINT8:
    case FIELD_UINT16:
    case FIELD_UINT32:
    case FIELD_IP4ADDR:
        f->val = data;
        break;
    case FIELD_UINT_STRING:
        f->val = mempool_copy(data, sizeof(struct uint_string));
        break;
    case FIELD_TIME_UINT16_256:
        f->val = UINT_TO_PTR(((uint16_t) PTR_TO_UINT(data)) / 256);
        break;
    default:
        break;
    }
    QUEUE_APPEND(head, f, link);
}

void field_add_packet_flags(struct field_head *head, char *key, uint16_t flags, void *data, int len)
{
    struct field *f;

    f = mempool_alloc(sizeof(*f));
    f->key = key;
    f->val = data;
    f->type = FIELD_PACKET_FLAGS;
    f->flags = flags;
    f->length = len;
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

const struct field *field_search(struct field_head *head, char *key)
{
    struct field *f = NULL;

    QUEUE_FOR_EACH(head, f, link) {
        if (strcmp(f->key, key) == 0)
            return f;
    }
    return NULL;
}

void *field_search_value(struct field_head *head, char *key)
{
    struct field *f = NULL;

    QUEUE_FOR_EACH(head, f, link) {
        if (strcmp(f->key, key) == 0)
            return f->val;
    }
    return NULL;
}

char *field_get_key(const struct field *f)
{
    return f ? f->key : NULL;
}

void *field_get_value(const struct field *f)
{
    return f ? f->val : NULL;
}

uint16_t field_get_type(const struct field *f)
{
    return f ? f->type : -1;
}

int field_get_length(const struct field *f)
{
    return f ? f->length : 0;
}

uint16_t field_get_flags(const struct field *f)
{
    return f ? f->flags : 0;
}

uint8_t field_get_uint8(const struct field *f)
{
    if (f && f->type == FIELD_UINT8)
        return (uint8_t) PTR_TO_UINT(field_get_value(f));
    return 0;
}

uint16_t field_get_uint16(const struct field *f)
{
    if (f && (f->type == FIELD_UINT16 || f->type == FIELD_TIME_UINT16_256))
        return (uint16_t) PTR_TO_UINT(field_get_value(f));
    return 0;
}

uint32_t field_get_uint32(const struct field *f)
{
    if (f && (f->type == FIELD_UINT32 || f->type == FIELD_IP4ADDR))
        return (uint32_t) PTR_TO_UINT(field_get_value(f));
    return 0;
}
