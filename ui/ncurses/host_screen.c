#define _GNU_SOURCE
#include <stdlib.h>
#include <arpa/inet.h>
#include "host_screen.h"
#include "menu.h"
#include "jomon.h"
#include "hashmap.h"
#include "decoder/host_analyzer.h"
#include "decoder/packet_arp.h"
#include "attributes.h"
#include "geoip.h"
#include "actionbar.h"
#include "portability.h"

#define IP_ADDR 0
#define ADDR_WIDTH 20
#define MAC 1
#define MAC_WIDTH 22
#define NAME 1
#define NAME_WIDTH 80
#define INFO 2
#define INFO_WIDTH 10
#define NATION 2
#define NATION_WIDTH 20
#define CITY 3

extern main_menu *menu;

enum page {
    LOCAL,
    REMOTE,
    NUM_PAGES
};

static void host_screen_init(screen *s);
static void host_screen_refresh(screen *s);
static void host_screen_got_focus(screen *s, screen *oldscr UNUSED);
static void host_screen_lost_focus(screen *s UNUSED, screen *newscr UNUSED);
static unsigned int host_screen_get_size(screen *s);
static void host_screen_render(host_screen *hs);
static void host_screen_get_input(screen *s);
static void update_host(struct host_info *host, bool new_host);
static void print_host_header(host_screen *hs);
static void print_all_hosts(host_screen *hs);
static void print_host(host_screen *hs, struct host_info *host, int y);

static screen_operations hsop = {
    .screen_init = host_screen_init,
    .screen_free = host_screen_free,
    .screen_refresh = host_screen_refresh,
    .screen_get_input = host_screen_get_input,
    .screen_got_focus = host_screen_got_focus,
    .screen_lost_focus = host_screen_lost_focus,
    .screen_get_data_size = host_screen_get_size
};

static screen_header local_header[] = {
    { "IP address", ADDR_WIDTH, HDR_INCREASING },
    { "MAC address", MAC_WIDTH, -1 },
    { "Info", INFO_WIDTH, -1 }
};

static screen_header remote_header[] = {
    { "IP address", ADDR_WIDTH, HDR_INCREASING },
    { "Name", NAME_WIDTH, -1 },
    { "Nation", NATION_WIDTH, -1 },
    { "City", INFO_WIDTH, -1 }
};

static inline int cmp_addr(const void *p1, const void *p2)
{
    int64_t res = (int64_t) ntohl((* (struct host_info **) p1)->ip4_addr) -
        (int64_t) ntohl((* (struct host_info **) p2)->ip4_addr);

    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

static inline int cmp_mac(const void *p1, const void *p2)
{
    unsigned char *m1 = (*(struct host_info **) p1)->mac_addr;
    unsigned char *m2 = (*(struct host_info **) p2)->mac_addr;

    return memcmp(m1, m2, ETHER_ADDR_LEN);
}

static inline int cmp_name(const void *p1, const void *p2)
{
    char *s1 = (*(struct host_info **) p1)->name;
    char *s2 = (*(struct host_info **) p2)->name;

    if (s1 == NULL)
        s1 = "";
    if (s2 == NULL)
        s2 = "";
    return strcmp(s1, s2);
}

static int cmp_geoip(const void *p1, const void *p2, char *(*geoip_fn)(char *))
{
    char addr[INET_ADDRSTRLEN];
    char *s1, *s2, *t1, *t2;
    int res;

    inet_ntop(AF_INET, &((*(struct host_info **) p1)->ip4_addr), addr, INET_ADDRSTRLEN);
    t1 = s1 = geoip_fn(addr);
    inet_ntop(AF_INET, &((*(struct host_info **) p2)->ip4_addr), addr, INET_ADDRSTRLEN);
    t2 = s2 = geoip_fn(addr);
    if (s1 == NULL)
        s1 = "";
    if (s2 == NULL)
        s2 = "";
    res = strcmp(s1, s2);
    if (t1)
        free(t1);
    if (t2)
        free(t2);
    return res;
}

static int cmp_local(const void *p1, const void *p2, void *arg)
{
    int pos = PTR_TO_INT(arg);

    switch (pos) {
    case IP_ADDR:
        return local_header[pos].order == HDR_INCREASING ?
            cmp_addr(p1, p2) : cmp_addr(p2, p1);
    case MAC:
        return local_header[pos].order == HDR_INCREASING ?
            cmp_mac(p1, p2) : cmp_mac(p2, p1);
    case INFO:
        return local_header[pos].order == HDR_INCREASING ?
            cmp_name(p1, p2) : cmp_name(p2, p1);
    default:
        return 0;
    }
}

static int cmp_remote(const void *p1, const void *p2, void *arg)
{
    int pos = PTR_TO_INT(arg);

    switch (pos) {
    case IP_ADDR:
        return remote_header[pos].order == HDR_INCREASING ?
            cmp_addr(p1, p2) : cmp_addr(p2, p1);
    case NAME:
        return remote_header[pos].order == HDR_INCREASING ?
            cmp_name(p1, p2) : cmp_name(p2, p1);
    case NATION:
        return remote_header[pos].order == HDR_INCREASING ?
            cmp_geoip(p1, p2, geoip_get_country) : cmp_geoip(p2, p1, geoip_get_country);
    case CITY:
        return remote_header[pos].order == HDR_INCREASING ?
            cmp_geoip(p1, p2, geoip_get_city) : cmp_geoip(p2, p1, geoip_get_city);
    default:
        return 0;
    }
}

static void update_data(void)
{
    host_screen *hs = (host_screen *) screen_cache_get(HOST_SCREEN);
    screen *s = (screen *) hs;
    hashmap_t *hosts = (s->page == LOCAL) ? host_analyzer_get_local() :
        host_analyzer_get_remote();

    vector_clear(hs->screen_buf, NULL);
    if (hashmap_size(hosts)) {
        const hashmap_iterator *it;

        HASHMAP_FOREACH(hosts, it)
            vector_push_back(hs->screen_buf, it->data);
        QSORT(vector_data(hs->screen_buf), vector_size(hs->screen_buf),
              sizeof(struct host_info *), (s->page == LOCAL) ? cmp_local : cmp_remote,
              INT_TO_PTR(screen_get_active_header_focus(s)));
    }
}

host_screen *host_screen_create(void)
{
    host_screen *hs;

    hs = xmalloc(sizeof(host_screen));
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
    s->win = newwin(my - HEADER_HEIGHT - actionbar_getmaxy(actionbar), mx, HEADER_HEIGHT, 0);
    s->lines = my - HEADER_HEIGHT - actionbar_getmaxy(actionbar);
    s->page = LOCAL;
    s->num_pages = NUM_PAGES;
    s->header = local_header;
    s->header_size = ARRAY_SIZE(local_header);
    hs->whdr = newwin(HEADER_HEIGHT, mx, 0, 0);
    hs->y = 0;
    hs->screen_buf = vector_init(512);
    scrollok(s->win, TRUE);
    nodelay(s->win, TRUE);
    keypad(s->win, TRUE);
    add_subscription0(new_file_publisher, update_data);
}

void host_screen_free(screen *s)
{
    host_screen *hs = (host_screen *) s;

    delwin(hs->whdr);
    delwin(s->win);
    vector_free(hs->screen_buf, NULL);
    free(hs);
}

void host_screen_refresh(screen *s)
{
    host_screen *hs = (host_screen *) s;

    if (s->resize) {
        int my, mx;

        getmaxyx(stdscr, my, mx);
        if (my > HEADER_HEIGHT - actionbar_getmaxy(actionbar))
            wresize(s->win, my - HEADER_HEIGHT - actionbar_getmaxy(actionbar), mx);
        s->resize = false;
    }
    werase(s->win);
    werase(hs->whdr);
    hs->y = 0;
    wbkgd(s->win, get_theme_colour(BACKGROUND));
    wbkgd(hs->whdr, get_theme_colour(BACKGROUND));
    host_screen_render(hs);
}

void host_screen_get_input(screen *s)
{
    int c = wgetch(s->win);
    host_screen *hs = (host_screen *) s;
    switch (c) {
    case KEY_ENTER:
    case '\n':
        if (s->tab_active) {
            if (s->page == LOCAL)
                screen_update_order(s, vector_data(hs->screen_buf),
                                    vector_size(hs->screen_buf), cmp_local);
            else
                screen_update_order(s, vector_data(hs->screen_buf),
                                    vector_size(hs->screen_buf), cmp_remote);
            host_screen_refresh(s);
        }
        break;
    case 'p':
        if (s->page == LOCAL) {
            s->header = remote_header;
            s->header_size = ARRAY_SIZE(remote_header);
        } else {
            s->header = local_header;
            s->header_size = ARRAY_SIZE(local_header);
        }
        s->page = (s->page + 1) % s->num_pages;
        s->top = 0;
        update_data();
        host_screen_refresh(s);
        break;
    default:
        ungetch(c);
        screen_get_input(s);
        break;
    }
}

void host_screen_got_focus(screen *s, screen *oldscr UNUSED)
{
    host_analyzer_subscribe(update_host);
    actionbar_refresh(actionbar, s);
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
    touchwin(hs->whdr);
    touchwin(hs->base.win);
    if (ctx.capturing || vector_size(hs->screen_buf) == 0)
        update_data();
    print_host_header(hs);
    print_all_hosts(hs);
}

void update_host(struct host_info *host, bool new_host)
{
    host_screen *hs = (host_screen *) screen_cache_get(HOST_SCREEN);

    if ((hs->base.page == LOCAL && host->local) || (hs->base.page == REMOTE && !host->local)) {
        if (new_host) {
            werase(hs->whdr);
            werase(hs->base.win);
            print_host_header(hs);
            vector_push_back(hs->screen_buf, host);
            QSORT(vector_data(hs->screen_buf), vector_size(hs->screen_buf),
                  sizeof(struct host_info *), hs->base.page == LOCAL ? cmp_local : cmp_remote,
                  INT_TO_PTR(screen_get_active_header_focus((screen *) hs)));
            hs->y = 0;
            print_all_hosts(hs);
        } else {
            int y = 0;

            while (y < hs->base.lines && hs->base.top + y < vector_size(hs->screen_buf)) {
                if (vector_get(hs->screen_buf, hs->base.top + y) == host) {
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
    int x = 0;
    screen *s = (screen *) hs;

    if (hs->base.page == LOCAL)
        mvprintat(hs->whdr, 0, 0, get_theme_colour(HEADER_TXT), "Local hosts");
    else
        mvprintat(hs->whdr, 0, 0, get_theme_colour(HEADER_TXT), "Remote hosts");
    wprintw(hs->whdr,  ": %d", vector_size(hs->screen_buf));
    for (unsigned int i = 0; i < s->header_size; i++) {
        mvwprintw(hs->whdr, HEADER_HEIGHT -1, x, "%s", s->header[i].txt);
        x += s->header[i].width;
    }
    screen_render_header_focus(s, hs->whdr);
    wrefresh(hs->whdr);
}

void print_all_hosts(host_screen *hs)
{
    int i = hs->base.top;

    while (hs->y < hs->base.lines && i < vector_size(hs->screen_buf)) {
        print_host(hs, vector_get(hs->screen_buf, i), hs->y);
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
        if (country) {
            mvwprintw(hs->base.win, y, ADDR_WIDTH + NAME_WIDTH, "%s", country);
            free(country);
        }
        if (city) {
            mvwprintw(hs->base.win, y, ADDR_WIDTH + NAME_WIDTH + NATION_WIDTH, "%s", city);
            free(city);
        }
    }
}
