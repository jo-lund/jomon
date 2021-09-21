#ifndef TERMINAL_H
#define TERMINAL_H

#include <stdbool.h>

struct termsize {
    unsigned short row;
    unsigned short col;
};

bool get_termsize(struct termsize *sz);

#endif
