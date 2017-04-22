#include "stat_screen.h"
#include "layout_int.h"
#include "../misc.h"
#include "../interface.h"
#include "../decoder/decoder.h"
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
static bool show_packet_stats = true;

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
    screen *s = screen_cache[STAT_SCREEN];

    if (s->focus) {
        alarm(1);
    }
}

void ss_handle_input()
{
    WINDOW *win = screen_cache[STAT_SCREEN]->win;
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
    case 'p':
        show_packet_stats = !show_packet_stats;
        ss_print();
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
    WINDOW *win = screen_cache[STAT_SCREEN]->win;
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
    if (show_packet_stats) {
        mvwprintw(win, ++y, 0, "");
        if (pstat.num_packets) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%23s %12s", "Packets", "Bytes");
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "Total");
            wprintw(win, ": %8u", pstat.num_packets);
            wprintw(win, "%13llu", pstat.tot_bytes);
        }
        if (pstat.num_arp) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "ARP");
            wprintw(win, ": %8u", pstat.num_arp);
            wprintw(win, "%13llu", pstat.bytes_arp);
        }
        if (pstat.num_stp) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "STP");
            wprintw(win, ": %8u", pstat.num_stp);
            wprintw(win, "%13llu", pstat.bytes_stp);
        }
        if (pstat.num_ip) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "IPv4");
            wprintw(win, ": %8u", pstat.num_ip);
            wprintw(win, "%13llu", pstat.bytes_ip);
        }
        if (pstat.num_ip6) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "IPv6");
            wprintw(win, ": %8u", pstat.num_ip6);
            wprintw(win, "%13llu", pstat.bytes_ip6);
        }
        if (pstat.num_icmp) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "ICMP");
            wprintw(win, ": %8u", pstat.num_icmp);
            wprintw(win, "%13llu", pstat.bytes_icmp);
        }
        if (pstat.num_igmp) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "IGMP");
            wprintw(win, ": %8u", pstat.num_igmp);
            wprintw(win, "%13llu", pstat.bytes_igmp);
        }
        if (pstat.num_pim) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "PIM");
            wprintw(win, ": %8u", pstat.num_pim);
            wprintw(win, "%13llu", pstat.bytes_pim);
        }
        if (pstat.num_tcp) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "TCP");
            wprintw(win, ": %8u", pstat.num_tcp);
            wprintw(win, "%13llu", pstat.bytes_tcp);
        }
        if (pstat.num_udp) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "UDP");
            wprintw(win, ": %8u", pstat.num_udp);
            wprintw(win, "%13llu", pstat.bytes_udp);
        }
        if (pstat.num_dns) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "DNS");
            wprintw(win, ": %8u", pstat.num_dns);
            wprintw(win, "%13llu", pstat.bytes_dns);
        }
        if (pstat.num_nbns) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "NBNS");
            wprintw(win, ": %8u", pstat.num_nbns);
            wprintw(win, "%13llu", pstat.bytes_nbns);
        }
        if (pstat.num_http) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "HTTP");
            wprintw(win, ": %8u", pstat.num_http);
            wprintw(win, "%13llu", pstat.bytes_http);
        }
        if (pstat.num_ssdp) {
            printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%13s", "SSDP");
            wprintw(win, ": %8u", pstat.num_ssdp);
            wprintw(win, "%13llu", pstat.bytes_ssdp);
        }
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
