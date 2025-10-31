#ifndef FIELD_H
#define FIELD_H

struct field_head;

enum field_type {
    FIELD_UINT8,
    FIELD_UINT16,
    FIELD_STRING,
    FIELD_UINT_STRING,
    FIELD_BYTES,
    FIELD_HWADDR,
    FIELD_IPADDR
};

void field_init(struct field_head *head);
void field_add_value(struct field_head *head, char *key, int type, void *data);
void field_add_bytes(struct field_head *head, char *key, int type, unsigned char *data, int len);
const struct field *field_get_next(struct field_head *head, const struct field *f);
bool field_empty(struct field_head *head);
const struct field *field_search(struct field_head *head, char *key);
void *field_search_value(struct field_head *head, char *key);
char *field_get_key(const struct field *f);
void *field_get_value(const struct field *f);
int field_get_type(const struct field *f);
uint8_t field_get_uint8(const struct field *f);
uint16_t field_get_uint16(const struct field *f);

#endif
