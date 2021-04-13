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
#include <locale.h>
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
#include "debug_file.h"
#include "geoip.h"
#include "bpf/bpf_parser.h"
#include "bpf/pcap_parser.h"
#include "bpf/genasm.h"

#define TABLE_SIZE 65536
#define SHORT_OPTS "F:i:f:r:Gdhlpstv"
#define BPF_DUMP_MODES 3

enum bpf_dump_mode {
    BPF_DUMP_MODE_NONE,
    BPF_DUMP_MODE_ASM,
    BPF_DUMP_MODE_C,
    BPF_DUMP_MODE_INT
};

vector_t *packets;
main_context ctx;
static volatile sig_atomic_t signal_flag = 0;
static bool fd_changed = false;
static bool promiscuous = false;
static bool ncurses_initialized = false;
static iface_handle_t *handle = NULL;
static struct bpf_prog bpf;

static bool handle_packet(unsigned char *buffer, uint32_t n, struct timeval *t);
static void print_help(char *prg);
static void setup_signal(int signo, void (*handler)(int), int flags);
static void run(void);
static void print_bpf(void) NORETURN;

static void sig_alarm(int signo UNUSED)
{
    signal_flag = 1;
}

static void sig_int(int signo UNUSED)
{
    finish(1);
}

int main(int argc, char **argv)
{
    unsigned char buf[SNAPLEN];
    char *prg_name = argv[0];
    int opt;
    int idx;
    static struct option long_options[] = {
        { "help", no_argument, NULL, 'h' },
        { "interface", required_argument, NULL, 'i' },
        { "list-interfaces", no_argument, NULL, 'l' },
        { "no-geoip", no_argument, NULL, 'G' },
        { "statistics", no_argument, NULL, 's' },
        { "verbose", no_argument, NULL, 'v' },
        { NULL, 0, NULL, 0}
    };

    memset(&bpf, 0, sizeof(bpf));
    setlocale(LC_ALL, "");
    ctx.opt.use_ncurses = true;
    ctx.opt.nopromiscuous = false;
    ctx.opt.verbose = false;
    ctx.opt.load_file = false;
    ctx.opt.nogeoip = false;
    ctx.opt.show_statistics = false;
    while ((opt = getopt_long(argc, argv, SHORT_OPTS, long_options, &idx)) != -1) {
        switch (opt) {
        case 'F':
            ctx.filter_file = optarg;
            break;
        case 'G':
            ctx.opt.nogeoip = true;
            break;
        case 'd':
            ctx.opt.dmode++;
            break;
        case 'f':
            ctx.filter = optarg;
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
    if (ctx.filter && ctx.filter_file)
        err_quit("Cannot set both a filter expression and a filter file");
    if (ctx.opt.dmode > BPF_DUMP_MODES)
        err_quit("Only -d, -dd, and -ddd are accepted");
    setup_signal(SIGALRM, sig_alarm, SA_RESTART);
    setup_signal(SIGINT, sig_int, 0);
    mempool_init();
    decoder_init();
    debug_init();
    if (ctx.opt.use_ncurses) {
        tcp_analyzer_init();
        dns_cache_init();
        host_analyzer_init();
#ifdef __linux__
        if (!ctx.opt.load_file)
            process_init();
#endif
    }
    if (ctx.opt.use_ncurses || ctx.opt.load_file)
        packets = vector_init(TABLE_SIZE);
    if (ctx.filter_file) {
        bpf = bpf_assemble(ctx.filter_file);
        if (bpf.size == 0)
            err_quit("bpf_assemble error");
    } else if (ctx.filter) {
        bpf = pcap_compile(ctx.filter);
        if (bpf.size == 0)
            err_quit("pcap_compile error");
    }
    if (ctx.opt.dmode > BPF_DUMP_MODE_NONE)
        print_bpf();
    if (!ctx.device && !(ctx.device = get_default_interface()))
        err_quit("Cannot find active network device");
    if (!ctx.opt.nopromiscuous && !ctx.opt.load_file) {
        set_promiscuous(ctx.device, true);
        promiscuous = true;
    }
    ctx.local_addr = malloc(sizeof(struct sockaddr_in));
    get_local_address(ctx.device, (struct sockaddr *) ctx.local_addr);
    get_local_mac(ctx.device, ctx.mac);
    if (!ctx.opt.nogeoip && !geoip_init())
        exit(1);
    if (ctx.opt.load_file) {
        enum file_error err;
        FILE *fp;

        ctx.capturing = false;
        if ((fp = open_file(ctx.filename, "r", &err)) == NULL) {
            err_sys("Error: %s", ctx.filename);
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
        iface_activate(handle, ctx.device, &bpf);
        if (ctx.opt.use_ncurses) {
            ncurses_init(&ctx);
            ncurses_initialized = true;
        }
    }
    run();
    finish(0);
}

static void print_bpf(void)
{
    switch (ctx.opt.dmode) {
    case BPF_DUMP_MODE_ASM:
        dumpasm(&bpf);
        break;
    case BPF_DUMP_MODE_C:
        for (int i = 0; i < bpf.size; i++)
            printf("{ 0x%x, %u, %u, 0x%08x },\n", bpf.bytecode[i].code, bpf.bytecode[i].jt,
                   bpf.bytecode[i].jf, bpf.bytecode[i].k);
        break;
    case BPF_DUMP_MODE_INT:
        printf("%u\n", bpf.size);
        for (int i = 0; i < bpf.size; i++)
            printf("%u %u %u %u\n", bpf.bytecode[i].code, bpf.bytecode[i].jt,
                   bpf.bytecode[i].jf, bpf.bytecode[i].k);
        break;
    default:
        break;
    }
    exit(0);
}

static void print_help(char *prg)
{
    printf("Usage: %s [-dhlpstvG] [-f filter] [-F filter-file] [-i interface] [-r path]\n"
           "Options:\n"
           "     -G, --no-geoip         Don't use GeoIP information\n"
           "     -d                     Dump packet filter as BPF assembly and exit\n"
           "     -dd                    Dump packet filter as C code fragment and exit\n"
           "     -ddd                   Dump packet filter as decimal numbers and exit\n"
           "     -F                     Read packet filter from file (BPF assembly)\n"
           "     -f                     Specify packet filter (tcpdump syntax)\n"
           "     -h, --help             Print this help summary\n"
           "     -i, --interface        Specify network interface\n"
           "     -l, --list-interfaces  List available interfaces\n"
           "     -p                     Don't put the interface into promiscuous mode\n"
           "     -r                     Read file in pcap format\n"
           "     -s, --statistics       Show statistics page\n"
           "     -t                     Use normal text output, i.e. don't use ncurses\n"
           "     -v, --verbose          Print verbose information\n",
           prg);
}

static void setup_signal(int signo, void (*handler)(int), int flags)
{
    struct sigaction act;

    act.sa_handler = handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = flags;
    if (sigaction(signo, &act, NULL) == -1) {
        err_sys("sigaction error");
    }
}

static void run(void)
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

void finish(int status)
{
    if (ncurses_initialized) {
        ncurses_end();
        vector_free(packets, NULL);
        tcp_analyzer_free();
        host_analyzer_free();
        dns_cache_free();
        debug_free();
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
    geoip_free();
    if (handle)
        free(handle);
    if (ctx.filter || ctx.filter_file) {
        if (bpf.bytecode)
            free(bpf.bytecode);
    }
    decoder_exit();
    exit(status);
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
    iface_activate(handle, ctx.device, &bpf);
    fd_changed = true;
}

bool handle_packet(unsigned char *buffer, uint32_t n, struct timeval *t)
{
    struct packet *p;

    if (bpf.size > 0) {
        if (bpf_run_filter(bpf, buffer, n) == 0) {
            return true;
        }
    }
    if (!decode_packet(buffer, n, &p)) {
        return false;
    }
    p->time.tv_sec = t->tv_sec;
    p->time.tv_usec = t->tv_usec;
    if (p->perr != DECODE_ERR) {
        tcp_analyzer_check_stream(p);
        host_analyzer_investigate(p);
    }
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
