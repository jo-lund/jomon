#include <ctype.h>
#include <string.h>
#include <limits.h>
#include "hexdump.h"
#include "layout.h"
#include "decoder/decoder.h"
#include "list.h"
#include "monitor.h"

#define HD_LIST_VIEW 0
#define HD_WINDOW 1
#define HD_NORMAL_LEN 76
#define HD_WIDE_LEN 75
#define HD_ASCII_IDX 60
#define BUFSZ 1024

// TODO: Remove this and make the elements modifiable
#define CYAN COLOR_PAIR(7)
#define GREEN COLOR_PAIR(3)
#define BROWN COLOR_PAIR(4)
#define BLUE COLOR_PAIR(5)
#define MAGENTA COLOR_PAIR(6)
#define LIGHT_BLUE (BLUE | A_BOLD)
#define PURPLE (MAGENTA | A_BOLD)
#define YELLOW (BROWN | A_BOLD)

typedef struct {
    int type;
    union {
        struct {
            list_view *lvw;
            list_view_header *header;
        };
        struct {
            WINDOW *win;
            struct packet *p;
            int y;
            int x;
        };
    } h_arg;
} hd_args;

struct hd_layer {
    char *name;
    int layer;
};

static const int hd_colour[] = {
    PURPLE,
    CYAN | A_BOLD,
    LIGHT_BLUE,
    GREEN | A_BOLD,
    YELLOW,
    BROWN
};

struct protocol_ctx {
    struct packet_data *pdata;
    struct protocol_info *pinfo;
    int layer;
    int idx;
    int prev_idx;
};

static list_t *protocols;

static void print_hexdump(enum hexmode mode, unsigned char *payload, uint16_t len, hd_args *arg);
static void print_char(WINDOW *win, char *buf, struct protocol_ctx *ctx, int i, int j, bool update);
static void print_protocol(WINDOW *win, struct hd_layer *prot);

void add_hexdump(list_view *lw, list_view_header *header, enum hexmode mode, unsigned char *payload, uint16_t len)
{
    hd_args args;

    args.type = HD_LIST_VIEW;
    args.h_arg.lvw = lw;
    args.h_arg.header = header;
    print_hexdump(mode, payload, len, &args);
}

void add_winhexdump(WINDOW *win, int y, int x, enum hexmode mode, struct packet *p)
{
    hd_args args;

    args.type = HD_WINDOW;
    args.h_arg.win = win;
    args.h_arg.p = p;
    args.h_arg.y = y;
    args.h_arg.x = x;
    print_hexdump(mode, p->buf, p->len, &args);
}

void print_hexdump(enum hexmode mode, unsigned char *payload, uint16_t len, hd_args *arg)
{
    int num = 0;
    char buf[1024];
    int hexoffset;
    char *hex = "0123456789abcdef";
    char *offset = " offset ";
    struct protocol_ctx ctx = { 0 };
    struct hd_layer *prot = malloc(sizeof(struct hd_layer));

    protocols = list_init(NULL);
    prot->name = "Ethernet";
    prot->layer = 0;
    list_push_back(protocols, prot);

    if (mode == HEXMODE_WIDE) {
        hexoffset = 64;
        snprintf(buf, 1024, "%-11s%s%s%s%s", offset, hex, hex, hex, hex);
    } else {
        hexoffset = 16;
        snprintf(buf, BUFSZ, "%-11s0  1  2  3  4  5  6  7", offset);
        if (arg->type == HD_LIST_VIEW) {
            snprintcat(buf, BUFSZ, "   8  9  a  b  c  d  e  f  %s", hex);
        } else {
            snprintcat(buf, BUFSZ, "   8  9  a  b  c  d  e  f   %s", hex);
        }
    }
    if (arg->type == HD_LIST_VIEW) {
        list_view_item *item;

        item = LV_ADD_TEXT_ELEMENT(arg->h_arg.lvw, arg->h_arg.header, "%s", buf);
        item->attr = A_BOLD;
    } else {
        mvprintat(arg->h_arg.win, arg->h_arg.y, arg->h_arg.x, A_BOLD, "%s", buf);
        ctx.pdata = arg->h_arg.p->root;
        ctx.pinfo = NULL;
        ctx.layer = 0;
        ctx.idx = ctx.pdata->len;
    }

    while (num < len) {
        snprintf(buf, BUFSZ, "%08x  ", num);
        if (mode == HEXMODE_NORMAL) {
            for (int i = num; i < num + hexoffset; i++) {
                if (i < len) {
                    snprintcat(buf, BUFSZ, "%02x ", payload[i]);
                } else {
                    snprintcat(buf, BUFSZ, "   ");
                }
                if (i % hexoffset - 7 == 0) snprintcat(buf, BUFSZ, " ");
            }
        }
        snprintcat(buf, BUFSZ, " ");
        for (int i = num; i < num + hexoffset; i++) {
            if (i < len) {
                if (isprint(payload[i])) {
                    snprintcat(buf, BUFSZ, "%c", payload[i]);
                } else {
                    snprintcat(buf, BUFSZ, ".");
                }
            } else {
                snprintcat(buf, BUFSZ, " ");
            }
        }
        if (arg->type == HD_LIST_VIEW) {
            LV_ADD_TEXT_ELEMENT(arg->h_arg.lvw, arg->h_arg.header, "%s", buf);
        } else {
            int i = 0;
            int x = arg->h_arg.x;
            int j = num;

            /* print offset */
            arg->h_arg.y++;
            while (i < 8) {
                mvwaddch(arg->h_arg.win, arg->h_arg.y, x++, buf[i]);
                i++;
            }

            if (mode == HEXMODE_NORMAL) {
                int k = 0;

                /* print hex values */
                while (i < HD_ASCII_IDX) {
                    if (isspace(buf[i])) {
                        waddch(arg->h_arg.win, buf[i]);
                    } else {
                        print_char(arg->h_arg.win, buf, &ctx, i, j, true);
                        if (k % 2) j++;
                        k++;
                    }
                    i++;
                }
                j = num;
                if (ctx.prev_idx != ctx.idx)
                    ctx.layer--;

                /* print ascii */
                waddch(arg->h_arg.win, ACS_VLINE);
                while (i < HD_NORMAL_LEN) {
                    if (isspace(buf[i])) {
                        waddch(arg->h_arg.win, buf[i]);
                    } else {
                        print_char(arg->h_arg.win, buf, &ctx, i, j++, false);
                    }
                    i++;
                }
                waddch(arg->h_arg.win, ACS_VLINE);
            } else { /* wide hex mode -- only print ascii */
                j = num;
                while (i < HD_WIDE_LEN) {
                    if (isspace(buf[i])) {
                        waddch(arg->h_arg.win, buf[i]);
                    } else {
                        print_char(arg->h_arg.win, buf, &ctx, i, j++, true);
                    }
                    i++;
                }
            }

            const node_t *n = list_begin(protocols);
            while (n) {
                struct hd_layer *prot;

                prot = (struct hd_layer *) list_data(n);
                print_protocol(arg->h_arg.win, prot);
                n = list_next(n);
            }
            list_clear(protocols, free);
        }
        num += hexoffset;
    }
    list_free(protocols, free);
}

void print_char(WINDOW *win, char *buf, struct protocol_ctx *ctx, int i, int j, bool update)
{
    if (update && j >= ctx->idx) {
        struct hd_layer *prot = malloc(sizeof(struct hd_layer));

        if (ctx->pdata->next) {
            ctx->pinfo = get_protocol(ctx->pdata->next->id);
            ctx->pdata = ctx->pdata->next;
            ctx->prev_idx = ctx->idx;
            ctx->idx += ctx->pdata->len;
            ctx->layer++;
            prot->name = ctx->pinfo->short_name;
            prot->layer = ctx->layer;
        } else {
            ctx->idx = INT_MAX;
            ctx->layer++;
            prot->name = "Data";
            prot->layer = ctx->layer;
        }
        list_push_back(protocols, prot);
    } else if (!update && j >= ctx->prev_idx) {
        ctx->prev_idx = ctx->idx;
        ctx->layer++;
    }
    waddch(win, buf[i] | hd_colour[ctx->layer]);
}

void print_protocol(WINDOW *win, struct hd_layer *prot)
{
    printat(win, hd_colour[prot->layer], "  %s", prot->name);
}
