#ifndef UTIL_H
#define UTIL_H

// TODO: Check for overflow

static inline long getval(unsigned char *tok, unsigned char *end, int base)
{
    long v = 0;

    while (tok < end)
        v = v * base + *tok++ - '0';
    return v;
}

static inline long gethexval(unsigned char *tok, unsigned char *end)
{
    long v = 0;

    while (tok < end) {
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
