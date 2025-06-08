#include <stdio.h>
#include <ctype.h>
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

static void print_hexdump(const unsigned char *src, uint32_t len, bool ascii)
{
    uint32_t num = 0;
    uint32_t offset = 0;

    if (!src)
        return;
    while (num < len) {
        printf("%10s0x%08x  ", " ", offset);
        for (uint32_t i = num; i < num + 16; i++) {
            if (i < len)
                printf("%02x ", src[i]);
            else
                printf("   ");
            if (i % 16 - 7 == 0)
                printf(" ");
        }
        if (!ascii) {
            printf("\n");
            num += 16;
            offset += 16;
            continue;
        }
        printf(" |");
        for (uint32_t i = num; i < num + 16; i++) {
            if (i < len) {
                if (isprint(src[i]))
                    printf("%c", src[i]);
                else
                    printf(".");
            } else {
                printf(" ");
            }
        }
        printf("|\n");
        num += 16;
        offset += 16;
    }
}

static void print_packet(const struct packet *p)
{
    char buf[MAXLINE];

    pkt2text(buf, MAXLINE, p);
    printf("%s\n", buf);
    if (ctx.opt.hexmode || ctx.opt.hex_asciimode) {
        if (ctx.opt.hexmode == HEX_PRINT_DGRAM ||
            ctx.opt.hex_asciimode == HEX_PRINT_DGRAM) {
            print_hexdump(get_dgram_payload(p), get_dgram_length(p),
                          ctx.opt.hex_asciimode);
        } else {
            print_hexdump(p->buf, p->len, ctx.opt.hex_asciimode);
        }
        printf("\n");
    }
}

CONSTRUCTOR static void text_register(void)
{
    ui_register(&text_ui, false);
}

void text_event(int event)
{
    if (event == UI_NEW_DATA)
        print_packet(vector_back(packets));
}

void text_draw(void)
{
    for (int i = 0; i < vector_size(packets); i++)
        print_packet(vector_get(packets, i));
    jomon_exit(0);
}
