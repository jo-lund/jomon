#include "stat_screen.h"
#include "layout_int.h"
#include "../misc.h"
#include "../interface.h"
#include "../decoder/decoder.h"
#include "help_screen.h"
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/wireless.h>
#endif
#include <ctype.h>

#define MAX_NAME 128

static const char *devpath = "/proc/net/dev";
static const char *statuspath = "/proc/self/status";
static const char *mempath = "/proc/meminfo";
static const char *cpupath = "/proc/cpuinfo";
static const char *statpath = "/proc/stat";

/* RX/TX variables read from /proc/net/dev */
typedef struct {
    unsigned long tot_bytes;
    unsigned long prev_bytes;
    unsigned long num_packets;
    unsigned long prev_packets;
    unsigned long errs;
    unsigned long drop;
    unsigned long fifo;
    unsigned long frame_cols;
    unsigned long compressed;
    unsigned long mc_carrier;
    double kbps; /* kilobytes per second */
    unsigned int pps; /* packets per second */
} linkdef;

typedef struct {
    unsigned long total_ram;
    unsigned long free_ram;
    unsigned long buffers;
    unsigned long cached;
    unsigned int vm_rss;
    int pid;
    int num_cpu;
    char cpu_name[MAX_NAME];
} hwstat;

typedef struct {
    unsigned long user;
    unsigned long nice;
    unsigned long system;
    unsigned long idle;
} cputime;

enum page {
    NET_STAT,
    HW_STAT
};

#define NUM_PAGES 2

extern main_context ctx;

// TODO: Make a stat_screen struct
static linkdef rx; /* data received */
static linkdef tx; /* data transmitted */
static hwstat hw;
static cputime **cpustat;
static int cpuidx = 0;
static bool show_packet_stats = true;
static enum page stat_page;

static bool read_hwstat();
static bool read_netstat();
static void calculate_rate();
static void print_netstat();
static void print_hwstat();
static void init_stat();
static void stat_screen_free();
static void stat_screen_init();
static void stat_screen_get_input(screen *s);
static void stat_screen_changed();

screen *stat_screen_create()
{
    static screen_operations op;

    op = SCREEN_OPS(.screen_init = stat_screen_init,
                     .screen_free = stat_screen_free,
                     .screen_get_input = stat_screen_get_input);
    return screen_create(&op);
}

void stat_screen_init(screen *s)
{
    screen_init(s);
    nodelay(s->win, TRUE);
    keypad(s->win, TRUE);
    add_subscription(screen_changed_publisher, stat_screen_changed);
    stat_page = NET_STAT;
    init_stat();
}

void stat_screen_free()
{
    for (int i = 0; i < hw.num_cpu; i++) {
        free(cpustat[i]);
    }
    free(cpustat);
    screen_free(screen_cache_get(STAT_SCREEN));
}

void stat_screen_changed()
{
    screen *s = screen_cache_get(STAT_SCREEN);

    if (s->focus) {
        memset(&rx, 0, sizeof(linkdef));
        memset(&tx, 0, sizeof(linkdef));
        stat_screen_print();
        alarm(1);
    }
}

void stat_screen_get_input(screen *s)
{
    int c = wgetch(s->win);

    switch (c) {
    case 'x':
    case KEY_ESC:
        alarm(0);
        pop_screen();
        break;
    case KEY_F(1):
    {
        screen *scr;

        alarm(0);
        if (!(scr = screen_cache_get(HELP_SCREEN))) {
            scr = help_screen_create();
            screen_cache_insert(HELP_SCREEN, scr);
            help_screen_render();
        }
        push_screen(scr);
        break;
    }
    case 'p':
        show_packet_stats = !show_packet_stats;
        stat_screen_print();
        break;
    case 'v':
        stat_page = (stat_page + 1) % NUM_PAGES;
        if (stat_page == NET_STAT) {
            memset(&rx, 0, sizeof(linkdef));
            memset(&tx, 0, sizeof(linkdef));
        }
        stat_screen_print();
        break;
    case 'q':
    case KEY_F(10):
        finish();
        break;
    default:
        break;
    }
}

void stat_screen_print()
{
    screen *s = screen_cache_get(STAT_SCREEN);

    if (s && s->focus) {
        werase(s->win);
        switch (stat_page) {
        case NET_STAT:
            print_netstat();
            break;
        case HW_STAT:
            print_hwstat();
            break;
        default:
            break;
        }
        wrefresh(s->win);
    }
}

void init_stat()
{
    FILE *fp;
    char buf[MAXLINE];

    memset(&rx, 0, sizeof(linkdef));
    memset(&tx, 0, sizeof(linkdef));
    memset(&hw, 0, sizeof(hwstat));
    if (!(fp = fopen(statpath, "r"))) {
        return;
    }
    while (fgets(buf, MAXLINE, fp)) {
        if (strncmp(buf, "cpu", 3) == 0) {
            if (isdigit(buf[3])) {
                hw.num_cpu++;
            }
        }
    }
    fclose(fp);
    if (!(fp = fopen(cpupath, "r"))) {
        return;
    }
    while (fgets(buf, MAXLINE, fp)) {
        if (strncmp(buf, "model name", 10) == 0) {
            int i = 10;
            int len;

            while (isspace(buf[i]) || buf[i] == ':') {
                i++;
            }
            len = strlen(buf + i) - 1;
            strncpy(hw.cpu_name, buf + i, len);
            hw.cpu_name[len] = '\0';
            break;
        }
    }
    fclose(fp);
    cpustat = malloc(hw.num_cpu * sizeof(cputime *));
    for (int i = 0; i < hw.num_cpu; i++) {
        cpustat[i] = calloc(2, sizeof(cputime));
    }
}

void print_netstat()
{
    int y = 0;
    struct iw_statistics iwstat;
    struct iw_range iwrange;
    screen *s = screen_cache_get(STAT_SCREEN);
    int hdrcol = get_theme_colour(HEADER_TXT);
    int subcol = get_theme_colour(SUBHEADER_TXT);

    read_netstat();
    calculate_rate();
    printat(s->win, y, 0, hdrcol, "Network statistics for %s", ctx.device);
    mvwprintw(s->win, ++y, 0, "");
    printat(s->win, ++y, 0, subcol, "%13s", "Upload rate");
    wprintw(s->win, ": %8.2f kB/s", tx.kbps);
    wprintw(s->win, "\t%4d packets/s", tx.pps);
    printat(s->win, ++y, 0, subcol, "%13s", "Download rate");
    wprintw(s->win, ": %8.2f kB/s", rx.kbps);
    wprintw(s->win, "\t%4d packets/s", rx.pps);

    if (get_iw_stats(ctx.device, &iwstat) && get_iw_range(ctx.device, &iwrange)) {
        mvwprintw(s->win, ++y, 0, "");
        printat(s->win, ++y, 0, subcol, "%13s", "Link quality");
        wprintw(s->win, ": %8u/%u", iwstat.qual.qual, iwrange.max_qual.qual);
        printat(s->win, ++y, 0, subcol, "%13s", "Level");
        wprintw(s->win, ": %8d dBm", (int8_t) iwstat.qual.level);
        printat(s->win, ++y, 0, subcol, "%13s", "Noise");
        wprintw(s->win, ": %8d dBm", (int8_t) iwstat.qual.noise);
    }
    if (show_packet_stats) {
        mvwprintw(s->win, ++y, 0, "");
        if (pstat[0].num_packets) {
            printat(s->win, ++y, 0, subcol, "%23s %12s", "Packets", "Bytes");
            for (int i = 0; i <= NUM_PROTOCOLS; i++) {
                if (pstat[i].num_packets) {
                    printat(s->win, ++y, 0, subcol, "%13s", pstat[i].protocol);
                    wprintw(s->win, ": %8u", pstat[i].num_packets);
                    wprintw(s->win, "%13llu", pstat[i].num_bytes);
                }
            }
        }
    }
}

void print_hwstat()
{
    int y = 0;
    unsigned long idle;
    screen *s = screen_cache_get(STAT_SCREEN);
    int hdrcol = get_theme_colour(HEADER_TXT);
    int subcol = get_theme_colour(SUBHEADER_TXT);

    read_hwstat();
    printat(s->win, y, 0, hdrcol, "Memory and CPU statistics");
    mvwprintw(s->win, ++y, 0, "");
    printat(s->win, ++y, 0, subcol, "%20s", "Total memory");
    wprintw(s->win, ": %8lu kB", hw.total_ram);
    printat(s->win, ++y, 0, subcol, "%20s", "Memory used");
    wprintw(s->win, ": %8lu kB", hw.total_ram - hw.free_ram);
    printat(s->win, -1, -1, subcol, "%10s", "Buffers");
    wprintw(s->win, ": %6lu kB", hw.buffers);
    printat(s->win, -1, -1, subcol, "%8s", "Cache");
    wprintw(s->win, ": %8lu kB", hw.cached);
    mvwprintw(s->win, ++y, 0, "");
    printat(s->win, ++y, 0, subcol, "%20s", "Process memory (RSS)");
    wprintw(s->win, ": %8lu kB", hw.vm_rss);
    printat(s->win, -1, -1, subcol, "%6s", "Pid");
    wprintw(s->win, ": %d", hw.pid);
    mvwprintw(s->win, ++y, 0, "");
    if (cpustat[0][0].idle != 0 && cpustat[0][1].idle != 0) {
        for (int i = 0; i < hw.num_cpu; i++) {
            idle = cpustat[i][!cpuidx].idle - cpustat[i][cpuidx].idle;
            printat(s->win, ++y, 0, subcol, "CPU%d idle", i);
            wprintw(s->win, ": %5d %%", idle);
        }
    }
}

bool read_netstat()
{
    FILE *fp;
    char buf[MAXLINE];
    int n;

    if (!(fp = fopen(devpath, "r"))) {
        return false;
    }
    n = strlen(ctx.device);
    while (fgets(buf, MAXLINE, fp)) {
        int i = 0;

        /* remove leading spaces */
        while (isspace(buf[i])) {
            i++;
        }
        if (strncmp(buf + i, ctx.device, n) == 0) {
            sscanf(buf + i + n + 1,
                   "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                   &rx.tot_bytes, &rx.num_packets, &rx.errs, &rx.drop, &rx.fifo,
                   &rx.frame_cols,&rx.compressed, &rx.mc_carrier, &tx.tot_bytes,
                   &tx.num_packets, &tx.errs, &tx.drop, &tx.fifo, &tx.frame_cols,
                   &tx.mc_carrier, &tx.compressed);
            break;
        }
    }
    fclose(fp);
    return true;
}

bool read_hwstat()
{
    FILE *fp;
    char buf[MAXLINE];
    int cpu = 0;

    /* get memory statistics */
    if (!(fp = fopen(mempath, "r"))) {
        return false;
    }
    while (fgets(buf, MAXLINE, fp)) {
        int i = 0;

        if (strncmp(buf, "MemTotal:", 9) == 0) {
            i += 9;
            while (isspace(buf[i])) {
                i++;
            }
            sscanf(buf + i, "%lu", &hw.total_ram);
        } else if (strncmp(buf, "MemFree:", 8) == 0) {
            i += 8;
            while (isspace(buf[i])) {
                i++;
            }
            sscanf(buf + i, "%lu", &hw.free_ram);
        } else if (strncmp(buf, "Buffers:", 8) == 0) {
            i += 8;
            while (isspace(buf[i])) {
                i++;
            }
            sscanf(buf + i, "%lu", &hw.buffers);
        } else if (strncmp(buf, "Cached:", 7) == 0) {
            i += 7;
            while (isspace(buf[i])) {
                i++;
            }
            sscanf(buf + i, "%lu", &hw.cached);
        }
    }
    fclose(fp);

    /* get process memory statistics */
    if (!(fp = fopen(statuspath, "r"))) {
        return false;
    }
    while (fgets(buf, MAXLINE, fp)) {
        int i = 0;

        if (strncmp(buf, "Pid:", 4) == 0) {
            i += 4;
            while (isspace(buf[i])) {
                i++;
            }
            sscanf(buf + i, "%u", &hw.pid);
        }
        if (strncmp(buf, "VmRSS:", 6) == 0) {
            i += 6;
            while (isspace(buf[i])) {
                i++;
            }
            sscanf(buf + i, "%u", &hw.vm_rss);
        }
    }
    fclose(fp);

    /* get CPU statistics */
    if (!(fp = fopen(statpath, "r"))) {
        return false;
    }
    while (fgets(buf, MAXLINE, fp)) {
        if (strncmp(buf, "cpu", 3) == 0) {
            int i = 3;

            if (isdigit(buf[i])) {
                i++;
                while (isspace(buf[i])) {
                    i++;
                }
                sscanf(buf + i, "%lu %lu %lu %lu", &cpustat[cpu][cpuidx].user, &cpustat[cpu][cpuidx].nice,
                       &cpustat[cpu][cpuidx].system, &cpustat[cpu][cpuidx].idle);
                cpu++;
            }
        }
    }
    cpuidx = (cpuidx + 1) % 2;
    fclose(fp);
    return true;
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
