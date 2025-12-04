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
    fi->f = mempool_finish();
    for (int i = 0; i < vector_size(aidx); i++) {
        int idx = PTR_TO_INT(vector_get(aidx, i));
        fi->f[idx].val = mempool_copy(fi->f[idx].val, fi->f[idx].length);
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
    struct field f;

    f.key = key;
    f.type = type;
    f.flags = 0;
    switch (type) {
    case FIELD_UINT8:
    case FIELD_UINT16:
    case FIELD_UINT32:
    case FIELD_STRING:
    case FIELD_STRING_HEADER:
    case FIELD_IP4ADDR:
    case FIELD_TIMESTAMP:
    case FIELD_TIMESTAMP_NON_STANDARD:
        f.val = data;
        break;
    case FIELD_UINT_STRING:
    case FIELD_UINT_HEX_STRING:
        f.val = data;
        f.length = sizeof(struct uint_string);
        vector_push_back(aidx, INT_TO_PTR(fi->nfields));
        break;
    case FIELD_TIME_UINT16_256:
        f.val = UINT_TO_PTR(((uint16_t) PTR_TO_UINT(data)) / 256);
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
    return (const struct field *) &fi->f[i];
}

const struct field *field_search(struct field_info *fi, char *key)
{
    const struct field *f;

    for (int i = 0; i < fi->nfields; i++) {
        f = field_get(fi, i);
        if (strcmp(f->key, key) == 0)
            return f;
    }
    return NULL;
}

void *field_search_value(struct field_info *fi, char *key)
{
    const struct field *f;

    for (int i = 0; i < fi->nfields; i++) {
        f = field_get(fi, i);
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
    return f ? f->type : ~0;
}

int field_get_length(const struct field *f)
{
    return f ? f->length : 0;
}

bool field_bitfield_print_value(const struct field *f)
{
    return f ? f->print_bitvalue : false;
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
