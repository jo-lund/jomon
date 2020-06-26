#include <stdlib.h>
#include <arpa/inet.h>
#include "host_screen.h"
#include "menu.h"
#include "../misc.h"
#include "../hashmap.h"
#include "../decoder/host_analyzer.h"
#include "../decoder/packet_arp.h"
#include "../util.h"
#include "../attributes.h"
#include "../geoip.h"

#define HOST_HEADER 5
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

static void host_screen_init(screen *s);
static void host_screen_refresh(screen *s);
static void host_screen_got_focus(screen *s UNUSED, screen *oldscr UNUSED);
static void host_screen_lost_focus(screen *s UNUSED, screen *newscr UNUSED);
static unsigned int host_screen_get_size(screen *s);
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
    .screen_get_input = screen_get_input,
    .screen_got_focus = host_screen_got_focus,
    .screen_lost_focus = host_screen_lost_focus,
    .screen_get_data_size = host_screen_get_size
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

    screen_init(s);
    getmaxyx(stdscr, my, mx);
    s->win = newwin(my - HOST_HEADER - STATUS_HEIGHT, mx, HOST_HEADER, 0);
    s->lines = my - HOST_HEADER - STATUS_HEIGHT;
    s->page = LOCAL;
    s->num_pages = NUM_PAGES;
    hs->header = newwin(HOST_HEADER, mx, 0, 0);
    hs->y = 0;
    hs->screen_buf = vector_init(1024);
    scrollok(s->win, TRUE);
    nodelay(s->win, TRUE);
    keypad(s->win, TRUE);
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
    hs->y = 0;
    vector_clear(hs->screen_buf, NULL);
    wbkgd(s->win, get_theme_colour(BACKGROUND));
    wbkgd(hs->header, get_theme_colour(BACKGROUND));
    host_screen_render(hs);
}

void host_screen_got_focus(screen *s UNUSED, screen *oldscr UNUSED)
{
    host_analyzer_subscribe(update_host);
}

void host_screen_lost_focus(screen *s UNUSED, screen *newscr UNUSED)
{
    host_analyzer_unsubscribe(update_host);
}

static unsigned int host_screen_get_size(screen *s)
{
    return vector_size(((host_screen *) s)->screen_buf);
}

void host_screen_render(host_screen *hs)
{
    hashmap_t *hosts = (hs->base.page == LOCAL) ? host_analyzer_get_local() :
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

    if ((hs->base.page == LOCAL && host->local) || (hs->base.page == REMOTE && !host->local)) {
        if (new_host) { // TODO: What if a user has scrolled the screen?
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

            while (y < hs->base.lines && hs->base.top + y < vector_size(hs->screen_buf)) {
                if (vector_get_data(hs->screen_buf, hs->base.top + y) == host) {
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

    if (hs->base.page == LOCAL) {
        printat(hs->header, y, 0, get_theme_colour(HEADER_TXT), "Local hosts");
    } else {
        printat(hs->header, y, 0, get_theme_colour(HEADER_TXT), "Remote hosts");
    }
    wprintw(hs->header,  ": %d", vector_size(hs->screen_buf));
    y += 4;
    mvwprintw(hs->header, y, 0, "IP address");
    if (hs->base.page == LOCAL) {
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
    int i = hs->base.top;

    while (hs->y < hs->base.lines && i < vector_size(hs->screen_buf)) {
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
    if (hs->base.page == LOCAL) {
        mvwprintw(hs->base.win, y, 0, "%-*s%s", ADDR_WIDTH, addr, mac);
        if (host->name) {
            mvwprintw(hs->base.win, y, ADDR_WIDTH + MAC_WIDTH, "%s", host->name);
        }
    } else if (hs->base.page == REMOTE) {
        char *country = geoip_get_country(addr);
        char *city = geoip_get_city(addr);

        mvwprintw(hs->base.win, y, 0, "%s", addr);
        if (host->name)
            mvwprintw(hs->base.win, y, ADDR_WIDTH, "%s", host->name);
        if (country)
            mvwprintw(hs->base.win, y, ADDR_WIDTH + NAME_WIDTH, "%s", country);
        if (city)
            mvwprintw(hs->base.win, y, ADDR_WIDTH + NAME_WIDTH + NATION_WIDTH, "%s", city);
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
