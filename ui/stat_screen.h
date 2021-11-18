#ifndef STAT_SCREEN_H
#define STAT_SCREEN_H

#include "layout_int.h"

struct screen;

struct screen *stat_screen_create(void);
void stat_screen_print(struct screen *s);

#endif
