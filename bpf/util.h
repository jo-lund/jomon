#ifndef UTIL_H
#define UTIL_H

#include <limits.h>
#include <stdbool.h>

static inline long getval(unsigned char *tok, const unsigned char *end, int base, bool *error)
{
    long v = 0;
    unsigned int d;

    if (base != 10 && base != 8) {
        *error = true;
        return -1;
    }
    *error = false;
    while (tok < end) {
        d = *tok++ - '0';
        if (base == 10 &&
            (v > UINT_MAX / 10 || (v == UINT_MAX / 10 && d > UINT_MAX % 10))) {
            *error = true;
            return -1;
        }
        if (base == 8 && v > 03777777777U) {
            *error = true;
            return -1;
        }
        v = v * base + d;
    }
    return v;
}

static inline long gethexval(unsigned char *tok, const unsigned char *end, bool *error)
{
    long v = 0;

    *error = false;
    while (tok < end) {
        if (v > 0xfffffffU) {
            *error = true;
            return -1;
        }
        if (*tok >= 'A' && *tok <= 'F')
            v = v * 16 + *tok++ - 'A' + 10;
        else if (*tok >= 'a' && *tok <= 'f')
            v = v * 16 + *tok++ - 'a' + 10;
        else
            v = v * 16 + *tok++ - '0';
    }
    return v;
}

#endif
