#include "stat_screen.h"
#include "layout_int.h"
#include "../misc.h"
#include "../interface.h"
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/wireless.h>
#endif

static const char *netpath = "/sys/class/net";
static const char *var_path[4] = {
    "statistics/rx_bytes",
    "statistics/rx_packets",
    "statistics/tx_bytes",
    "statistics/tx_packets"
};

static char path[4][64];

enum {
    RX_BYTES,
    RX_PACKETS,
    TX_BYTES,
    TX_PACKETS
};

/* RX/TX variables read from /sys/class/net */
typedef struct {
    unsigned long long tot_bytes;
    unsigned long long prev_bytes;
    unsigned long long num_packets;
    unsigned long long prev_packets;
    unsigned int bad_packets;
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
    for (int i = 0; i < 4; i++) {
        snprintf(path[i], 64, "%s/%s/%s", netpath, ctx.device, var_path[i]);
    }
    alarm(1);
}

void ss_handle_input(int c)
{
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
        wprintw(win, ": %3u/%u", iwstat.qual.qual, iwrange.max_qual.qual);
        printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Level");
        wprintw(win, ": %3u dBm", iwstat.qual.level);
        printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Noise");
        wprintw(win, ": %3u dBm", iwstat.qual.noise);
    }
    wrefresh(win);
}

// TODO: The reading of files needs to be improved. Should read from /proc/net/dev instead
bool read_stats()
{
    FILE *fp;

    if (!(fp = fopen(path[RX_BYTES], "r"))) {
        return false;
    }
    fscanf(fp, "%llu", &rx.tot_bytes);
    fclose(fp);
    if (!(fp = fopen(path[RX_PACKETS], "r"))) {
        return false;
    }
    fscanf(fp, "%llu", &rx.num_packets);
    fclose(fp);

    if (!(fp = fopen(path[TX_BYTES], "r"))) {
        return false;
    }
    fscanf(fp, "%llu", &tx.tot_bytes);
    fclose(fp);
    if (!(fp = fopen(path[TX_PACKETS], "r"))) {
        return false;
    }
    fscanf(fp, "%llu", &tx.num_packets);
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
    rx.kbps = (rx.tot_bytes - rx.prev_bytes) / 1024;
    tx.kbps = (tx.tot_bytes - tx.prev_bytes) / 1024;
    rx.pps = rx.num_packets - rx.prev_packets;
    tx.pps = tx.num_packets - tx.prev_packets;
    rx.prev_bytes = rx.tot_bytes;
    tx.prev_bytes = tx.tot_bytes;
    rx.prev_packets = rx.num_packets;
    tx.prev_packets = tx.num_packets;
}
