#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>
#include "stat_screen.h"
#include "layout.h"
#include "interface.h"
#include "decoder/decoder.h"
#include "menu.h"
#include "screen.h"
#include "actionbar.h"
#include "monitor.h"
#include "system_information.h"
#include "ringbuffer.h"

#define KIB 1024
#define MIB (KIB * KIB)
#define TX_RATE_X 78
#define WIRELESS_Y 17
#define PACKETS_Y 21

enum page {
    NET_STAT,
    HW_STAT,
    NUM_PAGES
};

enum rate {
    KIBS,
    MIBS,
    GIBS,
    MBITS,
    GBITS,
    NUM_RATES
};

enum redraw {
    RATE,
    PACKETS,
    ALL,
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
static enum rate rate = MIBS;
static ringbuffer_t *rx_rate;
static ringbuffer_t *tx_rate;
static enum redraw redraw = ALL;
static bool wireless;

static void calculate_rate(void);
static void print_netstat(screen *s);
static void print_hwstat(screen *s);
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

static void handle_alarm(void)
{
    screen *s = (screen *) screen_cache_get(STAT_SCREEN);

    if (s->focus)
        stat_screen_print(s);
}

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
    rx_rate = ringbuffer_init(60);
    tx_rate = ringbuffer_init(60);
    wireless = is_wireless(ctx.device);
    add_subscription0(alarm_publisher, handle_alarm);
}

void stat_screen_free(screen *s)
{
    for (int i = 0; i < 2; i++)
        free(cpustat[i]);
    free(cpustat);
    ringbuffer_free(rx_rate);
    ringbuffer_free(tx_rate);
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
    int c;

    switch (s->page) {
    case NET_STAT:
        c = wgetch(s->win);
        switch (c) {
        case 'e':
            formatted_output = !formatted_output;
            redraw = PACKETS;
            stat_screen_print(s);
            break;
        case 'E':
            rate = (rate + 1) % NUM_RATES;
            redraw = RATE;
            stat_screen_print(s);
            break;
        case 'v':
            show_packet_stats = !show_packet_stats;
            redraw = PACKETS;
            stat_screen_print(s);
            break;
        default:
            ungetch(c);
            screen_get_input(s);
            break;
        }
        redraw = ALL;
        break;
    case HW_STAT:
        screen_get_input(s);
        break;
    default:
        break;
    }
}

void stat_screen_print(screen *s)
{
    if (redraw == ALL)
        werase(s->win);
    switch (s->page) {
    case NET_STAT:
        print_netstat(s);
        break;
    case HW_STAT:
        print_hwstat(s);
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
        mvprintat(s->win, ++*y, 5, subcol, "%10s", pinfo->short_name);
        wprintw(s->win, ": %8u", pinfo->num_packets);
        if (formatted_output)
            wprintw(s->win, "%14s", format_bytes(pinfo->num_bytes, buf, 16));
        else
            wprintw(s->win, "%14" PRIu64, pinfo->num_bytes);
    }
}

static void print_rate(screen *s, struct linkdef *link)
{
    switch (rate) {
    case KIBS:
        wprintw(s->win, ": %8.2f kiB/s", link->kbps);
        break;
    case MIBS:
        wprintw(s->win, ": %8.2f MiB/s", link->kbps / KIB);
        break;
    case GIBS:
        wprintw(s->win, ": %8.2f GiB/s", link->kbps / MIB);
        break;
    case MBITS:
        wprintw(s->win, ": %8.2f Mibit/s", link->kbps / KIB * 8);
        break;
    case GBITS:
        wprintw(s->win, ": %8.2f Gibit/s", link->kbps / MIB * 8);
        break;
    default:
        break;
    }
}

static int get_colour(unsigned int val, unsigned int limit)
{
	if (val <= limit / 3)
		return 3;
	if (val < (limit - (limit / 3)))
		return 4;
    return 2;
}

static void print_graph(screen *s, int col, ringbuffer_t *rate, int y, int x, char *info, ...)
{
    unsigned int max, step;
    int ry, rx;
    unsigned int pps, mpps;
    int m;
    char buf[MAXLINE];
    va_list ap;

    va_start(ap, info);
    vsnprintf(buf, MAXLINE - 1, info, ap);
    va_end(ap);
    ry = y + 12;
    rx = x + 2;
    pps = PTR_TO_UINT(ringbuffer_first(rate));
    mpps = 10;
    for (int i = 0; i < ringbuffer_size(rate); i++) {
        if (pps > mpps)
            mpps = pps;
        pps = PTR_TO_UINT(ringbuffer_next(rate));
    }
    step = (mpps - 1) / 10 + 1;
    max = step * 10;
    for (unsigned int i = 0, j = 0; j <= 10; i += step, j++) {
        if (i > 0)
            mvwprintw(s->win, ry - j, rx, "%5d", i);
        mvwaddch(s->win, ry - j, rx + 5, ACS_VLINE);
    }
    pps = PTR_TO_UINT(ringbuffer_first(rate));
    for (int i = 0; i < ringbuffer_size(rate); i++) {
        for (unsigned int j = 0, k = 0; j < max && j < pps; j += step, k++) {
            wattron(s->win, col);
            mvwaddch(s->win, ry - k, i + rx + 6, ACS_CKBOARD);
            wattroff(s->win, col);
        }
        pps = PTR_TO_UINT(ringbuffer_next(rate));
    }
    m = (rx + rx + 68) / 2 - (strlen(buf) / 2);
    mvwprintw(s->win, ++ry, m, "%s", buf);
}

static void print_packet_stat(screen *s, int col, int y)
{
    char buf[16];

    if (total_packets) {
        y += 2;
        mvprintat(s->win, y, 5, col, "%20s %13s", "Packets", "Bytes");
        mvprintat(s->win, ++y, 5, col, "%10s", "Total");
        wprintw(s->win, ": %8u", total_packets);
        if (formatted_output)
            wprintw(s->win, "%14s", format_bytes(total_bytes, buf, 16));
        else
            wprintw(s->win, "%14" PRIu64, total_bytes);
        traverse_protocols(print_protocol_stat, &y);
    }
}

void print_netstat(screen *s)
{
    int y;
    struct wireless stat;
    int hdrcol = get_theme_colour(HEADER_TXT);
    int subcol = get_theme_colour(SUBHEADER_TXT);

    switch (redraw) {
    case RATE:
        y = 2;
        wmove(s->win, y, 0);
        wclrtoeol(s->win);
        mvprintat(s->win, y, 2, subcol, "%13s", "Download rate");
        print_rate(s, &rx);
        mvprintat(s->win, y, TX_RATE_X, subcol, "%13s", "Upload rate");
        print_rate(s, &tx);
        break;
    case PACKETS:
        if (show_packet_stats) {
            y = wireless ? PACKETS_Y : WIRELESS_Y;
            print_packet_stat(s, subcol, y);
        } else {
            y = wireless ? PACKETS_Y : WIRELESS_Y;
            wmove(s->win, y, 0);
            wclrtobot(s->win);
        }
        break;
    case ALL:
    default:
        y = 0;
        get_netstat(ctx.device, &rx, &tx);
        calculate_rate();
        mvprintat(s->win, y++, 0, hdrcol, "Network statistics for %s", ctx.device);
        mvprintat(s->win, ++y, 2, subcol, "%13s", "Download rate");
        print_rate(s, &rx);
        print_graph(s, subcol, rx_rate, y, 0, "%4d packets/s", rx.pps);
        mvprintat(s->win, y, TX_RATE_X, subcol, "%13s", "Upload rate");
        print_rate(s, &tx);
        print_graph(s, subcol, tx_rate, y, TX_RATE_X, "%4d packets/s", tx.pps);
        y += 15;
        if (wireless && get_iwstat(ctx.device, &stat)) {
            mvprintat(s->win, ++y, 2, subcol, "%13s", "Link quality");
            wprintw(s->win, ": %8u/%u", stat.qual, stat.max_qual);
            mvprintat(s->win, ++y, 2, subcol, "%13s", "Level");
            wprintw(s->win, ": %8d dBm", (int8_t) stat.level);
            mvprintat(s->win, ++y, 2, subcol, "%13s", "Noise");
            wprintw(s->win, ": %8d dBm", (int8_t) stat.noise);
            y++;
        }
        if (show_packet_stats)
            print_packet_stat(s, subcol, y);
        break;
    }
    wnoutrefresh(s->win);
    doupdate();
}

void print_hwstat(screen *s)
{
    int y = 0;
    unsigned long idle;
    int hdrcol = get_theme_colour(HEADER_TXT);
    int subcol = get_theme_colour(SUBHEADER_TXT);
    char buf[16];

    get_memstat(&mem);
    get_cpustat(cpustat[cpuidx]);
    cpuidx = (cpuidx + 1) % 2;
    mvprintat(s->win, y++, 0, hdrcol, "Memory and CPU statistics");
    mvprintat(s->win, ++y, 0, subcol, "%18s", "Total memory");
    wprintw(s->win, ": %6s", format_bytes(mem.total_ram * 1024, buf, ARRAY_SIZE(buf)));
    mvprintat(s->win, ++y, 0, subcol, "%18s", "Memory used");
    wprintw(s->win, ": %6s", format_bytes((mem.total_ram - mem.free_ram) * 1024,
                                              buf, ARRAY_SIZE(buf)));
    printat(s->win, subcol, "%10s", "Buffers");
    wprintw(s->win, ": %6s", format_bytes(mem.buffers * 1024, buf, ARRAY_SIZE(buf)));
    printat(s->win, subcol, "%8s", "Cache");
    wprintw(s->win, ": %6s", format_bytes(mem.cached * 1024, buf, ARRAY_SIZE(buf)));
    y += 2;
    mvprintat(s->win, y, 0, subcol, "%18s", "Pid");
    wprintw(s->win, ":  %d", mem.proc.pid);
    mvprintat(s->win, ++y, 0, subcol, "%18s", "Resident set size");
    wprintw(s->win, ":  %s", format_bytes(mem.proc.vm_rss * 1024, buf, ARRAY_SIZE(buf)));
    mvprintat(s->win, y++, 29, subcol, "Virtual memory size");
    wprintw(s->win, ":  %s", format_bytes(mem.proc.vm_size * 1024, buf, ARRAY_SIZE(buf)));
    if (cpustat[0][0].idle != 0 && cpustat[1][0].idle != 0) {
        int cx, cy;
        unsigned int load;

        cx = 10;
        cy = y + 11;
        mvprintat(s->win, y + 1, 1, subcol, "CPU load");
        cy++;
        for (int i = 0; i < 10; i++) {
            mvwprintw(s->win, cy - i, 2, "%3d%%", (i + 1) * 10);
            waddch(s->win, ACS_VLINE);
        }
        mvwaddch(s->win, cy + 1, 6, ACS_VLINE);
        for (int i = 0; i < hw.num_cpu; i++) {
            cy = y + 13;
            idle = cpustat[!cpuidx][i].idle - cpustat[cpuidx][i].idle;
            load = (idle > 100) ? 0 : (100 - idle);
            for (unsigned int j = 0; j < load / 10.0; j++) {
                wattron(s->win, COLOR_PAIR(get_colour(j, 10)));
                mvwaddch(s->win, cy - j, cx, ACS_CKBOARD);
                wattroff(s->win, COLOR_PAIR(get_colour(j, 10)));
            }
            mvprintat(s->win, ++cy, cx - 2, subcol, "CPU%d", i);
            mvwprintw(s->win, ++cy, cx - 1, "%u", load);
            cx += 5;
        }
    }
    wnoutrefresh(s->win);
    doupdate();
}

void calculate_rate(void)
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
    ringbuffer_push(rx_rate, UINT_TO_PTR(rx.pps));
    tx.pps = tx.num_packets - tx.prev_packets;
    ringbuffer_push(tx_rate, UINT_TO_PTR(tx.pps));
    rx.prev_bytes = rx.tot_bytes;
    tx.prev_bytes = tx.tot_bytes;
    rx.prev_packets = rx.num_packets;
    tx.prev_packets = tx.num_packets;
}
