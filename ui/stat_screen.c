#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>
#include "stat_screen.h"
#include "layout_int.h"
#include "../interface.h"
#include "../decoder/decoder.h"
#include "menu.h"
#include "screen.h"
#include "actionbar.h"
#include "../monitor.h"
#include "../system_information.h"

enum page {
    NET_STAT,
    HW_STAT,
    NUM_PAGES
};

extern main_menu *menu;

static struct linkdef rx; /* data received */
static struct linkdef tx; /* data transmitted */
static struct memstat mem;
static struct hwstat hw;
static struct cputime **cpustat;
static int cpuidx = 0;
static bool show_packet_stats = true;
static bool formatted_output = true;

static void calculate_rate(void);
static void print_netstat(void);
static void print_hwstat(void);
static void stat_screen_free(screen *s);
static void stat_screen_init(screen *s);
static void stat_screen_get_input(screen *s);
static void stat_screen_refresh(screen *s);
static void stat_screen_got_focus();
static void stat_screen_lost_focus();

static screen_operations ssop = {
    .screen_init = stat_screen_init,
    .screen_free = stat_screen_free,
    .screen_refresh = stat_screen_refresh,
    .screen_get_input = stat_screen_get_input,
    .screen_got_focus = stat_screen_got_focus,
    .screen_lost_focus = stat_screen_lost_focus,
};

screen *stat_screen_create(void)
{
    return screen_create(&ssop);
}

void stat_screen_init(screen *s)
{
    int my, mx;

    screen_init(s);
    getmaxyx(stdscr, my, mx);
    s->win = newwin(my, mx, 0, 0);
    s->page = NET_STAT;
    s->num_pages = NUM_PAGES;
    nodelay(s->win, TRUE);
    keypad(s->win, TRUE);
    memset(&rx, 0, sizeof(rx));
    memset(&tx, 0, sizeof(tx));
    memset(&hw, 0, sizeof(hw));
    memset(&mem, 0, sizeof(mem));
    get_hwstat(&hw);
    cpustat = calloc(2, sizeof(struct cputime *));
    for (int i = 0; i < 2; i++)
        cpustat[i] = malloc(hw.num_cpu * sizeof(struct cputime));
}

void stat_screen_free(screen *s)
{
    for (int i = 0; i < 2; i++)
        free(cpustat[i]);
    free(cpustat);
    screen_free(s);
}

void stat_screen_refresh(screen *s)
{
    wbkgd(s->win, get_theme_colour(BACKGROUND));
    screen_refresh(s);
    memset(&rx, 0, sizeof(rx));
    memset(&tx, 0, sizeof(tx));
    for (int i = 0; i < 2; i++) {
        memset(cpustat[i], 0, hw.num_cpu * sizeof(struct cputime));
    }
    stat_screen_print(s);
}

void stat_screen_got_focus()
{
    alarm(1);
}

void stat_screen_lost_focus()
{
    alarm(0);
}

void stat_screen_get_input(screen *s)
{
    int c = wgetch(s->win);

    switch (c) {
    case 'e':
        formatted_output = !formatted_output;
        stat_screen_print(s);
        break;
    case 'v':
        show_packet_stats = !show_packet_stats;
        stat_screen_print(s);
        break;
    default:
        ungetch(c);
        screen_get_input(s);
        break;
    }
}

void stat_screen_print(screen *s)
{
    werase(s->win);
    switch (s->page) {
    case NET_STAT:
        print_netstat();
        break;
    case HW_STAT:
        print_hwstat();
        break;
    default:
        break;
    }
    actionbar_refresh(actionbar, s);
}

static void print_protocol_stat(struct protocol_info *pinfo, void *arg)
{
    int *y = arg;
    screen *s = screen_cache_get(STAT_SCREEN);
    int subcol = get_theme_colour(SUBHEADER_TXT);
    char buf[16];

    if (pinfo->num_packets) {
        printat(s->win, ++*y, 0, subcol, "%13s", pinfo->short_name);
        wprintw(s->win, ": %8u", pinfo->num_packets);
        if (formatted_output) {
            wprintw(s->win, "%13s",
                    format_bytes(pinfo->num_bytes, buf, 16));
        } else {
            wprintw(s->win, "%13" PRIu64, pinfo->num_bytes);
        }
    }
}

void print_netstat(void)
{
    int y = 0;
    struct wireless stat;
    screen *s = screen_cache_get(STAT_SCREEN);
    int hdrcol = get_theme_colour(HEADER_TXT);
    int subcol = get_theme_colour(SUBHEADER_TXT);

    get_netstat(ctx.device, &rx, &tx);
    calculate_rate();
    printat(s->win, y++, 0, hdrcol, "Network statistics for %s", ctx.device);
    printat(s->win, ++y, 0, subcol, "%13s", "Upload rate");
    wprintw(s->win, ": %8.2f kB/s", tx.kbps);
    wprintw(s->win, "\t%4d packets/s", tx.pps);
    printat(s->win, ++y, 0, subcol, "%13s", "Download rate");
    wprintw(s->win, ": %8.2f kB/s", rx.kbps);
    wprintw(s->win, "\t%4d packets/s", rx.pps);
    if (get_iwstat(ctx.device, &stat)) {
        y += 2;
        printat(s->win, ++y, 0, subcol, "%13s", "Link quality");
        wprintw(s->win, ": %8u/%u", stat.qual, stat.max_qual);
        printat(s->win, ++y, 0, subcol, "%13s", "Level");
        wprintw(s->win, ": %8d dBm", (int8_t) stat.level);
        printat(s->win, ++y, 0, subcol, "%13s", "Noise");
        wprintw(s->win, ": %8d dBm", (int8_t) stat.noise);
    }
    if (show_packet_stats) {
        char buf[16];

        if (total_packets) {
            y += 2;
            printat(s->win, y, 0, subcol, "%23s %12s", "Packets", "Bytes");
            printat(s->win, ++y, 0, subcol, "%13s", "Total");
            wprintw(s->win, ": %8u", total_packets);
            if (formatted_output) {
                wprintw(s->win, "%13s",
                        format_bytes(total_bytes, buf, 16));
            } else {
                wprintw(s->win, "%13" PRIu64, total_bytes);
            }
            traverse_protocols(print_protocol_stat, &y);
        }
    }
    wnoutrefresh(s->win);
    doupdate();
}

void print_hwstat(void)
{
    int y = 0;
    unsigned long idle;
    screen *s = screen_cache_get(STAT_SCREEN);
    int hdrcol = get_theme_colour(HEADER_TXT);
    int subcol = get_theme_colour(SUBHEADER_TXT);

    get_memstat(&mem);
    get_cpustat(cpustat[cpuidx]);
    cpuidx = (cpuidx + 1) % 2;
    printat(s->win, y++, 0, hdrcol, "Memory and CPU statistics");
    printat(s->win, ++y, 0, subcol, "%18s", "Total memory");
    wprintw(s->win, ": %8lu kB", mem.total_ram);
    printat(s->win, ++y, 0, subcol, "%18s", "Memory used");
    wprintw(s->win, ": %8lu kB", mem.total_ram - mem.free_ram);
    printat(s->win, -1, -1, subcol, "%10s", "Buffers");
    wprintw(s->win, ": %6lu kB", mem.buffers);
    printat(s->win, -1, -1, subcol, "%8s", "Cache");
    wprintw(s->win, ": %8lu kB", mem.cached);
    y += 2;
    printat(s->win, y, 0, subcol, "%18s", "Pid");
    wprintw(s->win, ":  %d", mem.proc.pid);
    printat(s->win, ++y, 0, subcol, "%18s", "Resident set size");
    wprintw(s->win, ":  %lu kB", mem.proc.vm_rss);
    printat(s->win, y++, 34, subcol, "Virtual memory size");
    wprintw(s->win, ":  %lu kB", mem.proc.vm_size);
    if (cpustat[0][0].idle != 0 && cpustat[1][0].idle != 0) {
        for (int i = 0; i < hw.num_cpu; i++) {
            idle = cpustat[!cpuidx][i].idle - cpustat[cpuidx][i].idle;
            printat(s->win, ++y, 0, subcol, " CPU%d idle", i);
            wprintw(s->win, ": %4lu %%", idle);
        }
    }
    wnoutrefresh(s->win);
    doupdate();
}

void calculate_rate()
{
    if (!rx.prev_bytes && !tx.prev_bytes) {
        rx.prev_bytes = rx.tot_bytes;
        tx.prev_bytes = tx.tot_bytes;
        rx.prev_packets = rx.num_packets;
        tx.prev_packets = tx.num_packets;
        return;
    }
    rx.kbps = (double) (rx.tot_bytes - rx.prev_bytes) / 1024;
    tx.kbps = (double) (tx.tot_bytes - tx.prev_bytes) / 1024;
    rx.pps = rx.num_packets - rx.prev_packets;
    tx.pps = tx.num_packets - tx.prev_packets;
    rx.prev_bytes = rx.tot_bytes;
    tx.prev_bytes = tx.tot_bytes;
    rx.prev_packets = rx.num_packets;
    tx.prev_packets = tx.num_packets;
}
