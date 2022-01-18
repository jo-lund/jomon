#ifndef STRING_H
#define STRING_H

#include <stdint.h>
#include <string.h>

struct uint_string {
    uint32_t val;
    char *str;
};

static inline int cmp_val(const void *c1, const void *c2)
{
    return ((struct uint_string *) c1)->val - ((struct uint_string *) c2)->val;
}

static inline int cmp_str(const void *c1, const void *c2)
{
    return strcmp(((struct uint_string *) c1)->str, ((struct uint_string *) c2)->str);
}

/*
 * Concatenates fmt string to buf. Will never print passed the size of buf.
 * Expects buf to already contain a string or that buf is zeroed.
 *
 * Returns the number of bytes written.
 */
int snprintcat(char *buf, int size, char *fmt, ...);

/* Converts str to lower case */
char *string_tolower(char *str);

/* Find index of the last character 'c' in string. Return -1 if not found */
int string_find_last(const char *str, int c);

/*
 * Truncate string and add "..." at the end.
 *
 * len is the length of the string.
 * max is the maximum length the string can have.
*/
void string_truncate(char *str, size_t len, size_t max);

/*
 * Trim leading and trailing whitespace
*/
char *string_trim_whitespace(char *str);

#endif
