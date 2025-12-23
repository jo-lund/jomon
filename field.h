#ifndef FIELD_H
#define FIELD_H

#include <stdbool.h>

struct field;
struct field_info;

enum field_type {
    FIELD_UINT8,
    FIELD_UINT16,
    FIELD_UINT32,
    FIELD_UINT8_HEX,
    FIELD_UINT16_HEX,
    FIELD_UINT24_HEX,
    FIELD_UINT32_HEX,
    FIELD_STRING,
    FIELD_STRING_HEADER,
    FIELD_STRING_HEADER_INT,
    FIELD_STRING_HEADER_END,
    FIELD_UINT_STRING,
    FIELD_UINT_HEX_STRING,
    FIELD_BYTES,
    FIELD_HWADDR,
    FIELD_IP4ADDR,
    FIELD_IP6ADDR,
    FIELD_BITFIELD,
    FIELD_UINT16_HWADDR,
    FIELD_TIME_UINT16_256,
    FIELD_TIMESTAMP,
    FIELD_TIMESTAMP_SEC,
    FIELD_TIMESTAMP_NON_STANDARD
};

struct field_info *field_init(void);
void field_finish(struct field_info *fi);
void field_add_value(struct field_info *f, char *key, int type, void *data);
void field_add_bytes(struct field_info *f, char *key, int type, unsigned char *data, int len);
void field_add_bitfield(struct field_info *f, char *key, uint16_t flags,
                       bool print_value, void *data, int len);
const struct field *field_get(struct field_info *f, int i);
bool field_empty(struct field_info *f);
int field_count(struct field_info *f);
const struct field *field_search(struct field_info *f, char *key);
void *field_search_value(struct field_info *f, char *key);
struct field *field_get_next(const struct field *f);
char *field_get_key(const struct field *f);
void *field_get_value(const struct field *f);
uint16_t field_get_type(const struct field *f);
bool field_bitfield_print_value(const struct field *f);
uint16_t field_get_flags(const struct field *f);
int field_get_length(const struct field *f);
uint8_t field_get_uint8(const struct field *f);
uint16_t field_get_uint16(const struct field *f);
uint32_t field_get_uint32(const struct field *f);

#endif
