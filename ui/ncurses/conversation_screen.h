#ifndef CONVERSATION_H
#define CONVERSATION_H

#include "main_screen.h"

typedef struct {
    main_screen base;
    struct tcp_connection_v4 *stream;
} conversation_screen;

conversation_screen *conversation_screen_create(void);
void conversation_screen_free(screen *s);

#endif
