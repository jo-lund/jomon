#ifndef ACTIONBAR_H
#define ACTIONBAR_H

#include "layout_int.h"

typedef struct screen screen;

typedef struct actionbar {
    container base;
    bool visible;
} actionbar_t;

actionbar_t *actionbar_create(void);
void actionbar_free(actionbar_t *bar);
void actionbar_refresh(actionbar_t *bar, screen *s);
void actionbar_add(screen *s, char *key, char *text, bool disabled);
void actionbar_update(screen *s, char *key, char *text, bool disabled);
void actionbar_add_default(char *key, char *text, bool disabled);
int actionbar_getmaxy(actionbar_t *bar);

#endif
