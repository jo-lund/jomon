/* Network traffic monitor
 *
 * This program will monitor all incoming/outgoing network traffic and
 * give a log of the packets on the network.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include "misc.h"
#include "error.h"
#include "interface.h"
#include "ui/layout.h"
#include "decoder/packet.h"
#include "decoder/tcp_analyzer.h"
#include "vector.h"
#include "file.h"
#include "ui/protocols.h"
#include "mempool.h"
#include "decoder/host_analyzer.h"
#include "decoder/dns_cache.h"
#include "attributes.h"
#include "process.h"

#define TABLE_SIZE 65536

vector_t *packets;
main_context ctx;
static volatile sig_atomic_t signal_flag = 0;
static bool fd_changed = false;
static bool promiscuous = false;
static bool ncurses_initialized = false;
static iface_handle_t *handle = NULL;

static bool handle_packet(unsigned char *buffer, uint32_t n, struct timeval *t);
static void print_help(char *prg);
static void structures_init();
static void run();

int main(int argc, char **argv)
{
    unsigned char buf[SNAPLEN];
    char *prg_name = argv[0];
    int opt;
    int idx;
    static struct option long_options[] = {
        { "interface", required_argument, 0, 'i' },
        { "help", no_argument, 0, 'h' },
        { "list-interfaces", no_argument, 0, 'l' },
        { "no-geoip", no_argument, 0, 'G' },
        { "statistics", no_argument, 0, 's' },
        { "verbose", no_argument, 0, 'v' },
        { 0, 0, 0, 0}
    };

    ctx.opt.use_ncurses = true;
    ctx.opt.nopromiscuous = false;
    ctx.opt.verbose = false;
    ctx.opt.load_file = false;
    ctx.opt.nogeoip = false;
    ctx.opt.show_statistics = false;
    while ((opt = getopt_long(argc, argv, "i:r:Ghlpstv",
                              long_options, &idx)) != -1) {
        switch (opt) {
        case 'G':
            ctx.opt.nogeoip = true;
            break;
        case 'i':
            ctx.device = strdup(optarg);
            break;
        case 'l':
            list_interfaces();
            exit(0);
            break;
        case 'p':
            ctx.opt.nopromiscuous = true;
            break;
        case 'r':
            strcpy(ctx.filename, optarg);
            ctx.opt.load_file = true;
            break;
        case 's':
            ctx.opt.show_statistics = true;
            break;
        case 't':
            ctx.opt.use_ncurses = false;
            break;
        case 'v':
            ctx.opt.verbose = true;
            break;
        case 'h':
        default:
            print_help(prg_name);
            exit(0);
        }
    }
    structures_init();
    mempool_init();
    decoder_init();
    if (ctx.opt.use_ncurses) {
        tcp_analyzer_init();
        dns_cache_init();
        host_analyzer_init();
#ifdef __linux__
        if (!ctx.opt.load_file)
            process_init();
#endif
    }
    if (!ctx.device && !(ctx.device = get_default_interface())) {
        err_quit("Cannot find active network device");
    }
    if (!ctx.opt.nopromiscuous && !ctx.opt.load_file) {
        set_promiscuous(ctx.device, true);
        promiscuous = true;
    }
    ctx.local_addr = malloc(sizeof (struct sockaddr_in));
    get_local_address(ctx.device, (struct sockaddr *) ctx.local_addr);
    get_local_mac(ctx.device, ctx.mac);
    if (!ctx.opt.nogeoip && !(ctx.gi = GeoIP_open(GEOIP_PATH, GEOIP_STANDARD))) {
        exit(1);
    }
    if (ctx.opt.load_file) {
        enum file_error err;
        FILE *fp;

        ctx.capturing = false;
        if ((fp = open_file(ctx.filename, "r", &err)) == NULL) {
            err_sys("Error in %s", ctx.filename);
        }
        if ((err = read_file(fp, handle_packet)) != NO_ERROR) {
            fclose(fp);
            err_quit("Error in %s: %s", ctx.filename, get_file_error(err));
        }
        fclose(fp);
        if (ctx.opt.use_ncurses) {
            ncurses_init(&ctx);
            ncurses_initialized = true;
            handle = iface_handle_create();
            print_file();
        } else {
            for (int i = 0; i < vector_size(packets); i++) {
                char buf[MAXLINE];

                write_to_buf(buf, MAXLINE, vector_get_data(packets, i));
                printf("%s\n", buf);
            }
            finish(0);
        }
    } else {
        ctx.capturing = true;
        handle = iface_handle_create();
        handle->buf = buf;
        handle->len = SNAPLEN;
        handle->on_packet = handle_packet;
        iface_activate(handle, ctx.device);
        if (ctx.opt.use_ncurses) {
            ncurses_init(&ctx);
            ncurses_initialized = true;
        }
    }
    run();
    finish(0);
}

void print_help(char *prg)
{
    printf("Usage: %s [-lvhpstG] [-i interface] [-r path]\n", prg);
    printf("Options:\n");
    printf("     -G, --no-geoip         Don't use GeoIP information\n");
    printf("     -i, --interface        Specify network interface\n");
    printf("     -l, --list-interfaces  List available interfaces\n");
    printf("     -p                     Don't put the interface into promiscuous mode\n");
    printf("     -r                     Read file in pcap format\n");
    printf("     -s, --statistics       Show statistics page\n");
    printf("     -t                     Use normal text output, i.e. don't use ncurses\n");
    printf("     -v, --verbose          Print verbose information\n");
    printf("     -h                     Print this help summary\n");
}

void sig_alarm(int signo UNUSED)
{
    signal_flag = 1;
}

void sig_int(int signo UNUSED)
{
    finish(1);
}

void finish(int status)
{
    if (ncurses_initialized) {
        ncurses_end();
        vector_free(packets, NULL);
        tcp_analyzer_free();
        host_analyzer_free();
        dns_cache_free();
#ifdef __linux__
        if (!ctx.opt.load_file)
            process_free();
#endif
    }
    if (promiscuous) {
        set_promiscuous(ctx.device, false);
    }
    free(ctx.device);
    free(ctx.local_addr);
    if (handle && handle->sockfd > 0) {
        iface_close(handle);
    }
    mempool_free();
    if (ctx.gi) {
        GeoIP_delete(ctx.gi);
    }
    if (handle)
        free(handle);
    decoder_exit();
    exit(status);
}

void structures_init()
{
    struct sigaction act;

    /* set up an alarm and interrupt signal handler */
    act.sa_handler = sig_alarm;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGALRM, &act, NULL) == -1) {
        err_sys("sigaction error");
    }
    act.sa_handler = sig_int;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(SIGINT, &act, NULL) == -1) {
        err_sys("sigaction error");
    }

    /* Initialize table to store packets */
    if (ctx.opt.use_ncurses || ctx.opt.load_file) {
        packets = vector_init(TABLE_SIZE);
    }
}

void run()
{
    struct pollfd fds[] = {
        { handle->sockfd, POLLIN, 0 },
        { STDIN_FILENO, POLLIN, 0 }
    };

    while (1) {
        if (signal_flag) {
            signal_flag = 0;
            layout(ALARM);
            alarm(1);
        }
        if (fd_changed) {
            fds[0].fd = handle->sockfd;
            fd_changed = false;
        }
        if (poll(fds, 2, -1) == -1) {
            if (errno == EINTR) continue;
            err_sys("poll error");
        }
        if (fds[0].revents & POLLIN) {
            iface_read_packet(handle);
        }
        if (fds[1].revents & POLLIN) {
            handle_input();
        }
    }
}

void stop_scan()
{
    iface_close(handle);
    fd_changed = true;
}

void start_scan()
{
    clear_statistics();
    vector_clear(packets, NULL);
    free_packets(NULL);
    iface_activate(handle, ctx.device);
    fd_changed = true;
}

bool handle_packet(unsigned char *buffer, uint32_t n, struct timeval *t)
{
    struct packet *p;

    if (!decode_packet(buffer, n, &p)) {
        return false;
    }
    p->time.tv_sec = t->tv_sec;
    p->time.tv_usec = t->tv_usec;
    if (p->perr != DECODE_ERR) {
        tcp_analyzer_check_stream(p);
    }
    host_analyzer_investigate(p);
    if (ctx.capturing) {
        if (ctx.opt.use_ncurses) {
            vector_push_back(packets, p);
            layout(NEW_PACKET);
        } else {
            char buf[MAXLINE];

            write_to_buf(buf, MAXLINE, p);
            printf("%s\n", buf);
            free_packets(p);
        }
    } else {
        vector_push_back(packets, p);
    }
    return true;
}
