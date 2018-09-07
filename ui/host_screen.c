#include <stdlib.h>
#include "host_screen.h"
#include "menu.h"
#include "../misc.h"
#include "../hashmap.h"
#include "../decoder/host_analyzer.h"
#include "../decoder/packet_arp.h"

#define HOST_HEADER 3
#define ADDR_WIDTH 20

extern WINDOW *status;
extern main_menu *menu;

static void host_screen_init(screen *s);
static void host_screen_refresh(screen *s);
static void host_screen_get_input(screen *s);
static void host_screen_got_focus(screen *s);
static void host_screen_lost_focus(screen *s);
static void host_screen_render(host_screen *hs);
static void update_host(struct host_info *host, bool new_host);
static void print_host_header(host_screen *hs);
static void print_status();
static void print_all_hosts(host_screen *hs);
static void print_host(host_screen *hs, struct host_info *host, int y);

static screen_operations hsop = {
    .screen_init = host_screen_init,
    .screen_free = host_screen_free,
    .screen_refresh = host_screen_refresh,
    .screen_get_input = host_screen_get_input,
    .screen_got_focus = host_screen_got_focus,
    .screen_lost_focus = host_screen_lost_focus,
};

static int cmphost(const void *p1, const void *p2)
{
    return ntohl((* (struct host_info **) p1)->ip4_addr) -
        ntohl((* (struct host_info **) p2)->ip4_addr);
}

host_screen *host_screen_create()
{
    host_screen *hs;

    hs = malloc(sizeof(host_screen));
    hs->base.op = &hsop;
    host_screen_init((screen *) hs);
    return hs;
}

void host_screen_init(screen *s)
{
    int my, mx;
    host_screen *hs = (host_screen *) s;

    getmaxyx(stdscr, my, mx);
    hs->header = newwin(HOST_HEADER, mx, 0, 0);
    hs->base.win = newwin(my - HOST_HEADER - STATUS_HEIGHT, mx, HOST_HEADER, 0);
    hs->top = 0;
    hs->y = 0;
    hs->lines = my - HOST_HEADER - STATUS_HEIGHT;
    hs->screen_buf = vector_init(1024);
    scrollok(hs->base.win, TRUE);
    nodelay(hs->base.win, TRUE);
    keypad(hs->base.win, TRUE);
}

void host_screen_free(screen *s)
{
    host_screen *hs = (host_screen *) s;

    delwin(hs->header);
    delwin(s->win);
    vector_free(hs->screen_buf, NULL);
    free(hs);
}

void host_screen_refresh(screen *s)
{
    host_screen *hs = (host_screen *) s;

    werase(s->win);
    werase(hs->header);
    hs->top = 0;
    hs->y = 0;
    vector_clear(hs->screen_buf, NULL);
    wbkgd(s->win, get_theme_colour(BACKGROUND));
    wbkgd(hs->header, get_theme_colour(BACKGROUND));
    host_screen_render(hs);
}

void host_screen_get_input(screen *s)
{
    host_screen *hs = (host_screen *) s;
    int c = wgetch(s->win);
    int my = getmaxy(s->win);

    switch (c) {
    case 'x':
    case KEY_ESC:
    case KEY_F(3):
        pop_screen();
        break;
    case KEY_F(1):
        push_screen(screen_cache_get(HELP_SCREEN));
        break;
    case KEY_F(2):
        push_screen((screen *) menu);
        break;
    case KEY_UP:
        if (hs->top > 0) {
            hs->top--;
            wscrl(s->win, -1);
            wrefresh(hs->base.win);
        }
        break;
    case KEY_DOWN:
        if (hs->top + hs->lines < vector_size(hs->screen_buf)) {
            hs->top++;
            wscrl(s->win, 1);
            wrefresh(hs->base.win);
        }
        break;
    case ' ':
    case KEY_NPAGE:
        break;
    case 'b':
    case KEY_PPAGE:
        break;
    case 'q':
    case KEY_F(10):
        finish();
        break;
    default:
        break;
    }
}

void host_screen_got_focus(screen *s __attribute__((unused)))
{
    host_analyzer_subscribe(update_host);
}

void host_screen_lost_focus(screen *s __attribute__((unused)))
{
    host_analyzer_unsubscribe(update_host);
}

void host_screen_render(host_screen *hs)
{
    hash_map_t *hosts = host_analyzer_get_local();

    if (hash_map_size(hosts)) {
        const hash_map_iterator *it = hash_map_first(hosts);

        while (it) {
            vector_push_back(hs->screen_buf, it->data);
            it = hash_map_next(hosts, it);
        }
        qsort(vector_data(hs->screen_buf), vector_size(hs->screen_buf),
              sizeof(struct host_info *), cmphost);
    }
    touchwin(hs->header);
    touchwin(hs->base.win);
    print_host_header(hs);
    print_all_hosts(hs);
    print_status();
}

void update_host(struct host_info *host, bool new_host)
{
    host_screen *hs = (host_screen *) screen_cache_get(HOST_SCREEN);

    if (new_host) {
        werase(hs->header);
        werase(hs->base.win);
        print_host_header(hs);
        vector_push_back(hs->screen_buf, host);
        qsort(vector_data(hs->screen_buf), vector_size(hs->screen_buf),
              sizeof(struct host_info *), cmphost);
        hs->y = 0;
        print_all_hosts(hs);
    }
}

void print_host_header(host_screen *hs)
{
    int y = 0;

    printat(hs->header, y, 0, get_theme_colour(HEADER_TXT), "Local hosts");
    wprintw(hs->header,  ": %d", vector_size(hs->screen_buf));
    y += 2;
    mvwprintw(hs->header, y, 0, "IP address");
    mvwprintw(hs->header, y, ADDR_WIDTH, "MAC Address");
    mvwchgat(hs->header, y, 0, -1, A_STANDOUT, 0, NULL);
    wrefresh(hs->header);
}

void print_all_hosts(host_screen *hs)
{
    int i = hs->top;

    while (hs->y < hs->lines && i < vector_size(hs->screen_buf)) {
        print_host(hs, vector_get_data(hs->screen_buf, i), hs->y);
        hs->y++;
        i++;
    }
    wrefresh(hs->base.win);
}

void print_host(host_screen *hs, struct host_info *host, int y)
{
    char buf[MAXLINE];
    char addr[INET_ADDRSTRLEN];
    char mac[HW_ADDRSTRLEN];

    inet_ntop(AF_INET, &host->ip4_addr, addr, INET_ADDRSTRLEN);
    HW_ADDR_NTOP(mac, host->mac_addr);
    snprintf(buf, MAXLINE, "%-*s%s", ADDR_WIDTH, addr, mac);
    mvwprintw(hs->base.win, y, 0, "%s", buf);
}

void print_status()
{
    int colour = get_theme_colour(STATUS_BUTTON);

    werase(status);
    wbkgd(status, get_theme_colour(BACKGROUND));
    mvwprintw(status, 0, 0, "F1");
    printat(status, -1, -1, colour, "%-11s", "Help");
    wprintw(status, "F2");
    printat(status, -1, -1, colour, "%-11s", "Menu");
    wprintw(status, "F3");
    printat(status, -1, -1, colour, "%-11s", "Back");
    wprintw(status, "F10");
    printat(status, -1, -1, colour, "%-11s", "Quit");
    wrefresh(status);
}
