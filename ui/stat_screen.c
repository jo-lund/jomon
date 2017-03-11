#include "stat_screen.h"
#include "layout_int.h"
#include "../misc.h"
#include <string.h>
#include <unistd.h>

static const char *netpath = "/sys/class/net";
static const char *rx_bytes = "statistics/rx_bytes";
static const char *tx_bytes = "statistics/tx_bytes";

/* RX/TX variables */
typedef struct {
    unsigned long long tot_bytes;
    unsigned long long prev_bytes;
    unsigned int num_packets;
    unsigned int bad_packets;
    double kbps; /* kilobytes per second */
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

void ss_handle_input(int c)
{
    switch (c) {
    case 'q':
    case 'x':
    case KEY_ESC:
        alarm(0);
        pop_screen();
        break;
    case KEY_F(1):
        alarm(0);
        push_screen(HELP_SCREEN);
        break;
    default:
        break;
    }
}

void ss_print()
{
    int y = 0;
    WINDOW *win = screens[STAT_SCREEN]->win;

    werase(win);
    read_stats();
    calculate_rate();
    printat(win, y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Upload rate");
    wprintw(win, ": %8.2f kb/s", tx.kbps);
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Download rate");
    wprintw(win, ": %8.2f kb/s", rx.kbps);
    wrefresh(win);
}

bool read_stats()
{
    FILE *fp;
    char path[256];

    snprintf(path, 256, "%s/%s/%s", netpath, ctx.device, rx_bytes);
    if (!(fp = fopen(path, "r"))) {
        return false;
    }
    fscanf(fp, "%llu", &rx.tot_bytes);
    fclose(fp);

    snprintf(path, 256, "%s/%s/%s", netpath, ctx.device, tx_bytes);
    if (!(fp = fopen(path, "r"))) {
        return false;
    }
    fscanf(fp, "%llu", &tx.tot_bytes);
    fclose(fp);

    return true;
}

void calculate_rate()
{
    if (!rx.prev_bytes && !tx.prev_bytes) {
        rx.prev_bytes = rx.tot_bytes;
        tx.prev_bytes = tx.tot_bytes;
        return;
    }
    rx.kbps = (rx.tot_bytes - rx.prev_bytes) / 1024;
    tx.kbps = (tx.tot_bytes - tx.prev_bytes) / 1024;
    rx.prev_bytes = rx.tot_bytes;
    tx.prev_bytes = tx.tot_bytes;
}


