#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "field.h"
#include "queue.h"
#include "mempool.h"
#include "decoder/packet.h"
#include "string.h"
#include "util.h"
#include "vector.h"

struct field_info {
    struct field *f;
    int16_t nfields;
};

struct field {
    char *key;
    void *val;
    uint8_t type;
    bool print_bitvalue;
    uint16_t flags;
    int16_t length;
};

struct field_val {
    char *key;
    void *val;
};

static vector_t *aidx;

CONSTRUCTOR static void init(void)
{
    aidx = vector_init(32);
}

struct field_info *field_init(void)
{
    struct field_info *fi;

    fi = mempool_alloc(sizeof(*fi));
    fi->f = NULL;
    fi->nfields = 0;
    return fi;
}

void field_finish(struct field_info *fi)
{
    struct field *t;
    int i = 0, j = 0;

    fi->f = mempool_finish();
    t = fi->f;
    while (i < fi->nfields && j < vector_size(aidx)) {
        int idx = PTR_TO_INT(vector_get(aidx, j));
        if (idx == i) {
            t->val = mempool_copy(t->val, t->length);
            j++;
        }
        if (PTR_TO_UINT(t->val) & 0x1)
            t = (struct field *) ((char *) t + sizeof(struct field_val));
        else
            t = (struct field *) ((char *) t + sizeof(struct field));
        i++;
    }
    vector_clear(aidx, NULL);
}

void field_add_bytes(struct field_info *fi, char *key, int type, unsigned char *data, int len)
{
    struct field f;

    f.type = type;
    f.key = key;
    f.val = data;
    f.length = len;
    f.flags = 0;
    mempool_grow(&f, sizeof(f));
    vector_push_back(aidx, INT_TO_PTR(fi->nfields));
    fi->nfields++;
}

void field_add_value(struct field_info *fi, char *key, int type, void *data)
{
    switch (type) {
    case FIELD_UINT8:
    case FIELD_UINT16:
    case FIELD_UINT32:
    case FIELD_UINT8_HEX:
    case FIELD_UINT16_HEX:
    case FIELD_UINT24_HEX:
    case FIELD_UINT32_HEX:
    case FIELD_IP4ADDR:
    case FIELD_TIMESTAMP:
    case FIELD_TIMESTAMP_NON_STANDARD:
    {
        struct field_val f;
        f.key = key;
        f.val = UINT_TO_PTR(PTR_TO_UINT(data) << 9 | (uint8_t) type << 1 | 0x1);
        mempool_grow(&f, sizeof(f));
        fi->nfields++;
        return;
    }
    case FIELD_TIME_UINT16_256:
    {
        struct field_val f;
        f.key = key;
        f.val = UINT_TO_PTR((((uint16_t) PTR_TO_UINT(data)) / 256) << 9 |
                            (uint8_t) type << 1 | 0x1);
        mempool_grow(&f, sizeof(f));
        fi->nfields++;
        return;
    }
    default:
        break;
    }

    struct field f;
    f.key = key;
    f.type = type;
    f.flags = 0;
    switch (type) {
    case FIELD_STRING:
    case FIELD_STRING_HEADER:
        f.val = data;
        break;
    case FIELD_UINT_STRING:
    case FIELD_UINT_HEX_STRING:
        f.val = data;
        f.length = sizeof(struct uint_string);
        vector_push_back(aidx, INT_TO_PTR(fi->nfields));
        break;
    default:
        break;
    }
    mempool_grow(&f, sizeof(f));
    fi->nfields++;
}

void field_add_bitfield(struct field_info *fi, char *key, uint16_t flags,
                        bool print_value, void *data, int len)
{
    struct field f;

    f.key = key;
    f.val = data;
    f.type = FIELD_BITFIELD;
    f.print_bitvalue = print_value;
    f.flags = flags;
    f.length = len;
    mempool_grow(&f, sizeof(f));
    fi->nfields++;
}

bool field_empty(struct field_info *fi)
{
    return fi ? fi->nfields == 0 : true;
}

int field_count(struct field_info *fi)
{
    return fi->nfields;
}

const struct field *field_get(struct field_info *fi, int i)
{
    struct field *f;

    f = fi->f;
    for (int j = 0; j < fi->nfields; j++) {
        if (i == j)
            return (const struct field *) f;
        if (PTR_TO_UINT(f->val) & 0x1)
            f = (struct field *) ((char *) f + sizeof(struct field_val));
        else
            f = (struct field *) ((char *) f + sizeof(struct field));
    }
    return NULL;
}

const struct field *field_search(struct field_info *fi, char *key)
{
    struct field *f;

    f = fi->f;
    for (int i = 0; i < fi->nfields; i++) {
        if (strcmp(f->key, key) == 0)
            return (const struct field *) f;
        if (PTR_TO_UINT(f->val) & 0x1)
            f = (struct field *) ((char *) f + sizeof(struct field_val));
        else
            f = (struct field *) ((char *) f + sizeof(struct field));
    }
    return NULL;
}

void *field_search_value(struct field_info *fi, char *key)
{
    struct field *f;

    f = fi->f;
    for (int i = 0; i < fi->nfields; i++) {
        if (strcmp(f->key, key) == 0) {
            if (PTR_TO_UINT(f->val) & 0x1)
                return UINT_TO_PTR(PTR_TO_UINT(f->val) >> 9);
            else
                return f->val;
        }
        if (PTR_TO_UINT(f->val) & 0x1)
            f = (struct field *) ((char *) f + sizeof(struct field_val));
        else
            f = (struct field *) ((char *) f + sizeof(struct field));
    }
    return NULL;
}

char *field_get_key(const struct field *f)
{
    return f->key;
}

void *field_get_value(const struct field *f)
{
    return (PTR_TO_UINT(f->val) & 0x1) ? UINT_TO_PTR(PTR_TO_UINT(f->val) >> 9) : f->val;
}

uint16_t field_get_type(const struct field *f)
{
    return (PTR_TO_UINT(f->val) & 0x1) ? (PTR_TO_UINT(f->val) >> 1) & 0xff : f->type;
}

int field_get_length(const struct field *f)
{
    return (PTR_TO_UINT(f->val) & 0x1) ? 0 : f->length;
}

bool field_bitfield_print_value(const struct field *f)
{
    return (PTR_TO_UINT(f->val) & 0x1) ? false : f->print_bitvalue;
}

uint16_t field_get_flags(const struct field *f)
{
    return (PTR_TO_UINT(f->val) & 0x1) ? 0 : f->flags;
}

uint8_t field_get_uint8(const struct field *f)
{
    uint8_t type;

    type = field_get_type(f);
    if (type == FIELD_UINT8 || type == FIELD_UINT8_HEX)
        return (uint8_t) PTR_TO_UINT(field_get_value(f));
    return 0;
}

uint16_t field_get_uint16(const struct field *f)
{
    uint8_t type;

    type = field_get_type(f);
    if (type == FIELD_UINT16 || type == FIELD_UINT16_HEX ||
        type == FIELD_TIME_UINT16_256)
        return (uint16_t) PTR_TO_UINT(field_get_value(f));
    return 0;
}

uint32_t field_get_uint32(const struct field *f)
{
    uint8_t type;

    type = field_get_type(f);
    if (type == FIELD_UINT32 || type == FIELD_UINT32_HEX || type == FIELD_IP4ADDR)
        return (uint32_t) PTR_TO_UINT(field_get_value(f));
    return 0;
}
