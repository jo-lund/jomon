#include <stdlib.h>
#include <GeoIPCity.h>
#include "host_screen.h"
#include "menu.h"
#include "../misc.h"
#include "../hashmap.h"
#include "../decoder/host_analyzer.h"
#include "../decoder/packet_arp.h"
#include "../util.h"

#define HOST_HEADER 3
#define ADDR_WIDTH 20
#define MAC_WIDTH 22
#define NAME_WIDTH 80
#define NATION_WIDTH 20

extern WINDOW *status;
extern main_menu *menu;

enum page {
    LOCAL,
    REMOTE,
    NUM_PAGES
};

static enum page host_page;

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
static void scroll_page(host_screen *hs, int num_lines);

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
    int64_t res = (int64_t) ntohl((* (struct host_info **) p1)->ip4_addr) -
        (int64_t) ntohl((* (struct host_info **) p2)->ip4_addr);

    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
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

    host_page = LOCAL;
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
            print_host(hs, vector_get_data(hs->screen_buf, hs->top), 0);
            wrefresh(hs->base.win);
        }
        break;
    case KEY_DOWN:
        if (hs->top + hs->lines < vector_size(hs->screen_buf)) {
            hs->top++;
            wscrl(s->win, 1);
            print_host(hs, vector_get_data(hs->screen_buf, hs->top + hs->lines - 1),
                       hs->lines - 1);
            wrefresh(hs->base.win);
        }
        break;
    case ' ':
    case KEY_NPAGE:
        scroll_page(hs, my);
        break;
    case 'b':
    case KEY_PPAGE:
        scroll_page(hs, -my);
        break;
    case 'p':
        host_page = (host_page + 1) % NUM_PAGES;
        host_screen_refresh(s);
        break;
    case 'c':
        screen_stack_move_to_top(screen_cache_get(CONNECTION_SCREEN));
        break;
    case 's':
        screen_stack_move_to_top(screen_cache_get(STAT_SCREEN));
        break;
    case 'q':
    case KEY_F(10):
        finish(0);
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
    hashmap_t *hosts = (host_page == LOCAL) ? host_analyzer_get_local() :
        host_analyzer_get_remote();

    if (hashmap_size(hosts)) {
        const hashmap_iterator *it = hashmap_first(hosts);

        while (it) {
            vector_push_back(hs->screen_buf, it->data);
            it = hashmap_next(hosts, it);
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

    if ((host_page == LOCAL && host->local) || (host_page == REMOTE && !host->local)) {
        if (new_host) {
            werase(hs->header);
            werase(hs->base.win);
            print_host_header(hs);
            vector_push_back(hs->screen_buf, host);
            qsort(vector_data(hs->screen_buf), vector_size(hs->screen_buf),
                  sizeof(struct host_info *), cmphost);
            hs->y = 0;
            print_all_hosts(hs);
        } else {
            int y = 0;

            while (y < hs->lines && hs->top + y < vector_size(hs->screen_buf)) {
                if (vector_get_data(hs->screen_buf, hs->top + y) == host) {
                    wmove(hs->base.win, y, 0);
                    wclrtoeol(hs->base.win);
                    print_host(hs, host, y);
                    wrefresh(hs->base.win);
                    break;
                }
                y++;
            }
        }
    }
}

void print_host_header(host_screen *hs)
{
    int y = 0;

    if (host_page == LOCAL) {
        printat(hs->header, y, 0, get_theme_colour(HEADER_TXT), "Local hosts");
    } else {
        printat(hs->header, y, 0, get_theme_colour(HEADER_TXT), "Remote hosts");
    }
    wprintw(hs->header,  ": %d", vector_size(hs->screen_buf));
    y += 2;
    mvwprintw(hs->header, y, 0, "IP address");
    if (host_page == LOCAL) {
        mvwprintw(hs->header, y, ADDR_WIDTH, "MAC Address");
        mvwprintw(hs->header, y, ADDR_WIDTH + MAC_WIDTH, "Info");
    } else {
        mvwprintw(hs->header, y, ADDR_WIDTH, "Name");
        mvwprintw(hs->header, y, ADDR_WIDTH + NAME_WIDTH, "Nation");
        mvwprintw(hs->header, y, ADDR_WIDTH + NAME_WIDTH + NATION_WIDTH, "City");
    }
    mvwchgat(hs->header, y, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
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
    char addr[INET_ADDRSTRLEN];
    char mac[HW_ADDRSTRLEN];

    inet_ntop(AF_INET, &host->ip4_addr, addr, INET_ADDRSTRLEN);
    HW_ADDR_NTOP(mac, host->mac_addr);
    if (host_page == LOCAL) {
        mvwprintw(hs->base.win, y, 0, "%-*s%s", ADDR_WIDTH, addr, mac);
        if (host->name) {
            mvwprintw(hs->base.win, y, ADDR_WIDTH + MAC_WIDTH, "%s", host->name);
        }
    }
    if (host_page == REMOTE) {
        GeoIPRecord *record = NULL;

        if (ctx.gi) {
            record = GeoIP_record_by_addr(ctx.gi, addr);
        }
        mvwprintw(hs->base.win, y, 0, "%s", addr);
        if (host->name) {
            mvwprintw(hs->base.win, y, ADDR_WIDTH, "%s", host->name);
        }
        if (record) {
            if (record->country_name) {
                mvwprintw(hs->base.win, y, ADDR_WIDTH + NAME_WIDTH, "%s",
                          record->country_name);
            }
            if (record->city) {
                mvwprintw(hs->base.win, y, ADDR_WIDTH + NAME_WIDTH + NATION_WIDTH, "%s",
                          record->city);
            }
            GeoIPRecord_delete(record);
        }
    }
}

void scroll_page(host_screen *hs, int num_lines)
{
    int i = abs(num_lines);

    if (vector_size(hs->screen_buf) <= i) return;

    if (num_lines > 0) { /* scroll down */
        while (i > 0 && hs->top + hs->lines < vector_size(hs->screen_buf)) {
            hs->top++;
            i--;
        }
    } else { /* scroll up */
        while (i > 0 && hs->top > 0) {
            hs->top--;
            i--;
        }
    }
    if (i != abs(num_lines)) {
        hs->y = 0;
        werase(hs->base.win);
        print_all_hosts(hs);
    }
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
