#include <stdio.h>
#include "ui.h"
#include "print_protocol.h"
#include "jomon.h"
#include "vector.h"
#include "decoder/packet.h"

extern vector_t *packets;

static void text_draw(void);
static void text_event(int);

static struct ui text_ui = {
    .name = "text",
    .draw = text_draw,
    .event = text_event
};

CONSTRUCTOR static void text_register(void)
{
    ui_register(&text_ui, false);
}

void text_event(int event)
{
    if (event == UI_NEW_DATA) {
        char buf[MAXLINE];
        struct packet *p;

        p = vector_back(packets);
        pkt2text(buf, MAXLINE, p);
        printf("%s\n", buf);
    }
}

void text_draw(void)
{
    for (int i = 0; i < vector_size(packets); i++) {
        char buf[MAXLINE];

        pkt2text(buf, MAXLINE, vector_get(packets, i));
        printf("%s\n", buf);
    }
    jomon_exit(0);
}
