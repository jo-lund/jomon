#include "stat_screen.h"
#include "layout_int.h"
#include "../misc.h"
#include "../interface.h"
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/wireless.h>
#endif
#include <ctype.h>

static const char *devpath = "/proc/net/dev";

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

extern main_context ctx;
static linkdef rx; /* data received */
static linkdef tx; /* data transmitted */

static bool read_stats();
static void calculate_rate();

void ss_init()
{
    memset(&rx, 0, sizeof(linkdef));
    memset(&tx, 0, sizeof(linkdef));
    alarm(1);
}

void ss_changed()
{
    screen *s = screens[STAT_SCREEN];

    if (s->focus) {
        alarm(1);
    }
}

void ss_handle_input()
{
    WINDOW *win = screens[STAT_SCREEN]->win;
    int c = wgetch(win);

    switch (c) {
    case 'x':
    case KEY_ESC:
        alarm(0);
        pop_screen();
        break;
    case KEY_F(1):
        alarm(0);
        push_screen(HELP_SCREEN);
        break;
    case 'q':
    case KEY_F(10):
        finish();
        break;
    default:
        break;
    }
}

void ss_print()
{
    int y = 0;
    WINDOW *win = screens[STAT_SCREEN]->win;
    struct iw_statistics iwstat;
    struct iw_range iwrange;

    werase(win);
    read_stats();
    calculate_rate();
    printat(win, y, 0, COLOR_PAIR(4) | A_BOLD, "Network statistics for %s", ctx.device);
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Upload rate");
    wprintw(win, ": %8.2f kB/s", tx.kbps);
    wprintw(win, "\t%4d packets/s", tx.pps);
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Download rate");
    wprintw(win, ": %8.2f kB/s", rx.kbps);
    wprintw(win, "\t%4d packets/s", rx.pps);

    if (get_iw_stats(ctx.device, &iwstat) && get_iw_range(ctx.device, &iwrange)) {
        mvwprintw(win, ++y, 0, "");
        printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Link quality");
        wprintw(win, ": %8u/%u", iwstat.qual.qual, iwrange.max_qual.qual);
        printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Level");
        wprintw(win, ": %8d dBm", (int8_t) iwstat.qual.level);
        printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Noise");
        wprintw(win, ": %8d dBm", (int8_t) iwstat.qual.noise);
    }
    wrefresh(win);
}

bool read_stats()
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
