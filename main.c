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
#include "jomon.h"
#include "interface.h"
#include "decoder/packet.h"
#include "decoder/tcp_analyzer.h"
#include "vector.h"
#include "file.h"
#include "mempool.h"
#include "decoder/host_analyzer.h"
#include "decoder/dns_cache.h"
#include "process.h"
#include "geoip.h"
#include "bpf/bpf_parser.h"
#include "bpf/pcap_parser.h"
#include "bpf/genasm.h"
#include "ui/ui.h"
#include "timer.h"

#define SHORT_OPTS "F:b:i:f:r:DVdhnNpstvxX"
#define COUNT_OPT 128
#define BPF_DUMP_MODES 3

enum bpf_dump_mode {
    BPF_DUMP_MODE_NONE,
    BPF_DUMP_MODE_ASM,
    BPF_DUMP_MODE_C,
    BPF_DUMP_MODE_INT
};

vector_t *packets;
main_context ctx;
static volatile sig_atomic_t alarm_flag = 0;
static volatile sig_atomic_t winch_flag = 0;
static bool fd_changed = false;
static struct bpf_prog bpf;
static bool promiscuous_mode = false;

static bool handle_packet(iface_handle_t *handle, unsigned char *buf,
                          uint32_t n, struct timeval *t);
static void print_help_and_exit(void) NORETURN;
static void run(void) NORETURN;
static void print_bpf_and_exit(void) NORETURN;
static void handle_count_and_exit(unsigned char *buf) NORETURN;

static void sig_callback(int sig)
{
    switch (sig) {
    case SIGALRM:
        alarm_flag = 1;
        break;
    case SIGINT:
    case SIGQUIT:
        jomon_exit(1);
    case SIGWINCH:
        winch_flag = 1;
        break;
    default:
        break;
    }
}

static void setup_signal(int signo, void (*handler)(int), int flags)
{
    struct sigaction act;

    act.sa_handler = handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = flags;
    if (sigaction(signo, &act, NULL) == -1)
        err_sys("sigaction error");
}

static void load_file(unsigned char *buf, packet_handler ph)
{
    enum file_error err;
    FILE *fp;

    ctx.capturing = false;
    ctx.pcap_saved = true;
    ctx.handle = iface_handle_create(buf, SNAPLEN, ph);
    if ((fp = file_open(ctx.filename, "r", &err)) == NULL)
        err_sys("Error: %s", ctx.filename);
    if ((err = file_read(ctx.handle, fp, ph)) != NO_ERROR) {
        fclose(fp);
        err_quit("Error in %s: %s", ctx.filename, file_error(err));
    }
    fclose(fp);
}

static void activate_interface(unsigned char *buf, packet_handler ph)
{
    ctx.capturing = true;
    ctx.handle = iface_handle_create(buf, SNAPLEN, ph);
    iface_activate(ctx.handle, ctx.device, &bpf);
    if (!ctx.opt.nopromiscuous) {
        iface_set_promiscuous(ctx.handle, ctx.device, true);
        promiscuous_mode = true;
    }
}

int main(int argc, char **argv)
{
    unsigned char buf[SNAPLEN];
    int opt;
    int idx;
    static struct option long_options[] = {
        { "buffer-size", required_argument, NULL, 'b' },
        { "count", no_argument, NULL, COUNT_OPT },
        { "help", no_argument, NULL, 'h' },
        { "interface", required_argument, NULL, 'i' },
        { "list-interfaces", no_argument, NULL, 'D' },
        { "statistics", no_argument, NULL, 's' },
        { "verbose", no_argument, NULL, 'v' },
        { "version", no_argument, NULL, 'V' },
        { NULL, 0, NULL, 0}
    };

    memset(&bpf, 0, sizeof(bpf));
    setlocale(LC_ALL, "");
    while ((opt = getopt_long(argc, argv, SHORT_OPTS, long_options, &idx)) != -1) {
        switch (opt) {
        case 'D':
            list_interfaces();
            exit(0);
        case 'F':
            ctx.filter_file = optarg;
            break;
        case 'N':
            ctx.opt.no_domain = true;
            break;
        case 'V':
            printf("jomon version " VERSION "\n");
            exit(0);
        case 'X':
            ctx.opt.hex_asciimode++;
            break;
        case 'b':
            ctx.opt.buffer_size = atoi(optarg) * 1024;
            if (ctx.opt.buffer_size <= 0)
                err_quit("Invalid buffer size: %s", optarg);
            break;
        case 'd':
            ctx.opt.dmode++;
            break;
        case 'f':
            ctx.filter = optarg;
            break;
        case 'i':
            ctx.device = xstrdup(optarg);
            break;
        case 'n':
            ctx.opt.numeric = true;
            break;
        case 'p':
            ctx.opt.nopromiscuous = true;
            break;
        case 'r':
            strlcpy(ctx.filename, optarg, MAXPATH);
            ctx.opt.load_file = true;
            break;
        case 's':
            ctx.opt.show_statistics = true;
            break;
        case 't':
            ctx.opt.text_mode = true;
            break;
        case 'v':
            ctx.opt.verbose = true;
            break;
        case 'x':
            ctx.opt.hexmode++;
            break;
        case COUNT_OPT:
            ctx.opt.show_count = true;
            break;
        case 'h':
        default:
            print_help_and_exit();
        }
    }
    if (ctx.filter && ctx.filter_file)
        err_quit("Cannot set both a filter expression and a filter file");
    if (ctx.opt.dmode > BPF_DUMP_MODES)
        err_quit("Only -d, -dd, and -ddd are accepted");
    if ((ctx.opt.hexmode || ctx.opt.hex_asciimode) && !ctx.opt.text_mode)
        err_quit("-x and -X options are only valid in text mode (-t option)");
    if (ctx.opt.hexmode > HEX_PRINT_MODES)
        err_quit("Only -x and -xx are accepted");
    if (ctx.opt.hex_asciimode > HEX_PRINT_MODES)
        err_quit("Only -X and -XX are accepted");
    if (ctx.opt.hexmode > 0 && ctx.opt.hex_asciimode > 0)
        err_quit("Cannot combine -x and -X");
    setup_signal(SIGINT, sig_callback, 0);
    setup_signal(SIGQUIT, sig_callback, 0);
    mempool_init();
    debug_init();
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
        print_bpf_and_exit();
    if (!ctx.device && !(ctx.device = get_default_interface()))
        err_quit("Cannot find active network device");
    setup_signal(SIGALRM, sig_callback, SA_RESTART);
    if (ctx.opt.show_count)
        handle_count_and_exit(buf);
    decoder_init();
    tcp_analyzer_init();
    dns_cache_init();
    host_analyzer_init();
    packets = vector_init(PACKET_TABLE_SIZE);
    if (ctx.opt.text_mode) {
        ui_set_active("text");
    } else  {
        if (!ctx.opt.load_file || geteuid() == 0)
            process_init();
        setup_signal(SIGWINCH, sig_callback, 0);
    }
    ctx.local_addr = xmalloc(sizeof(struct sockaddr_in));
    get_local_address(ctx.device, (struct sockaddr *) ctx.local_addr);
    get_local_mac(ctx.device, ctx.mac);
    geoip_init();
    if (ctx.opt.load_file) {
        load_file(buf, handle_packet);
        ui_init();
        ui_draw();
    } else {
        activate_interface(buf, handle_packet);
        ui_init();
    }
    run();
}

static void print_bpf_and_exit(void)
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

static void print_help_and_exit(void)
{
    printf("jomon " VERSION "\n");
    printf("Usage: jomon [-dDhNnpstvVxX] [-b size] [-f filter] [-F filter-file]\n"
           "              [-i interface] [-r path]\n\n"
           "General options:\n"
           "    -b, --buffer-size <size>\n"
           "                      Set the kernel capture buffer size to <size>, in units of\n"
           "                      KiB (1024 bytes). Default: 4MB\n"
           "    --count           Print only the number of packets captured or read from file\n"
           "    -d                Dump packet filter as BPF assembly and exit\n"
           "    -dd               Dump packet filter as C code fragment and exit\n"
           "    -ddd              Dump packet filter as decimal numbers and exit\n"
           "    -D, --list-interfaces\n"
           "                      Print available interfaces and exit\n"
           "    -f <filter>       Specify packet filter (tcpdump syntax)\n"
           "    -F <filter file>  Read packet filter from file (BPF assembly)\n"
           "    -h, --help        Print this help summary\n"
           "    -i, --interface <interface>\n"
           "                      Set the network interface to <interface>. If not specified\n"
           "                      the first interface (excluding loopback) that is up and\n"
           "                      running will be used\n"
           "    -n                Use numerical addresses\n"
           "    -N                Only print the hostname (don't print the FQDN)\n"
           "    -p                Don't put the interface into promiscuous mode\n"
           "    -r <path>         Read file in pcap format\n"
           "    -s, --statistics  Show statistics page\n"
           "    -V, --version     Print version\n\n"
           "Text mode options:\n"
           "    -t                Use normal text output, i.e. don't use ncurses\n"
           "    -v, --verbose     Print verbose information\n"
           "    -x                Print the data of each packet in hex, minus its link-level\n"
           "                      header\n"
           "    -xx               Print the data of each packet in hex, including its\n"
           "                      link-level header\n"
           "    -X                Print the data of each packet in hex and ASCII, minus its\n"
           "                      link-level header\n"
           "    -XX               Print the data of each packet in hex and ASCII, including its\n"
           "                      link-level header");
    exit(0);
}

static void run(void)
{
    struct pollfd fds[] = {
        { ctx.handle->fd, POLLIN, 0 },
        { STDIN_FILENO, POLLIN, 0 }
    };

    alarm(1);
    while (1) {
        timer_run();
        if (alarm_flag) {
            alarm_flag = 0;
            ui_event(UI_ALARM);
            alarm(1);
        }
        if (winch_flag) {
            winch_flag = 0;
            setup_signal(SIGWINCH, NULL, SA_RESETHAND);
            ui_event(UI_RESIZE);
            setup_signal(SIGWINCH, sig_callback, 0);
        }
        if (fd_changed) {
            fds[0].fd = ctx.handle->fd;
            fd_changed = false;
        }
        if (poll(fds, 2, -1) == -1) {
            if (errno == EINTR)
                continue;
            err_sys("poll error");
        }
        if (fds[0].revents & POLLIN)
            iface_read_packet(ctx.handle);
        if (fds[0].revents & POLLERR) {
            int err;
            socklen_t len = sizeof(err);

            if (getsockopt(ctx.handle->fd, SOL_SOCKET, SO_ERROR, &err, &len) == -1)
                err_sys("getsockopt error");
            if (err != ENETDOWN) {
                DEBUG("poll: An error has occurred on the device");
                stop_capture();
            }
        }
        if (fds[1].revents & POLLIN)
            ui_event(UI_INPUT);
    }
}

void jomon_exit(int status)
{
    if (ctx.opt.show_count) {
        if (ctx.capturing)
            printf("\nNumber of packets captured: %u\n", ctx.packet_count);
        else
            printf("Number of packets: %u\n", ctx.packet_count);
    }
    ui_fini();
    vector_free(packets, NULL);
    if (!ctx.opt.text_mode && !ctx.opt.load_file)
        process_free();
    host_analyzer_free();
    dns_cache_free();
    debug_free();
    tcp_analyzer_free();
    if (promiscuous_mode)
        iface_set_promiscuous(ctx.handle, ctx.device, false);
    free(ctx.device);
    free(ctx.local_addr);
    mempool_destruct();
    geoip_free();
    if (ctx.handle) {
        if (ctx.handle->fd > 0)
            iface_close(ctx.handle);
        free(ctx.handle);
    }
    if (ctx.filter || ctx.filter_file) {
        if (bpf.bytecode)
            free(bpf.bytecode);
    }
    decoder_exit();
    exit(status);
}

void stop_capture(void)
{
    iface_close(ctx.handle);
    fd_changed = true;
    ctx.capturing = false;
}

void start_capture(void)
{
    if (!ctx.opt.nopromiscuous && !promiscuous_mode) {
        iface_set_promiscuous(ctx.handle, ctx.device, true);
        promiscuous_mode = true;
    }
    clear_statistics();
    vector_clear(packets, NULL);
    free_packets(NULL);
    process_clear_cache();
    iface_activate(ctx.handle, ctx.device, &bpf);
    fd_changed = true;
    ctx.capturing = true;
    ctx.opt.load_file = false;
}

static bool handle_packet(iface_handle_t *handle, unsigned char *buf, uint32_t n,
                          struct timeval *t)
{
    struct packet *p;

    if (bpf.size > 0) {
        if (bpf_run_filter(bpf, buf, n) == 0)
            return true;
    }
    if (!decode_packet(handle, buf, n, &p))
        return false;
    p->time.tv_sec = t->tv_sec;
    p->time.tv_usec = t->tv_usec;
    tcp_analyzer_check_stream(p);
    host_analyzer_investigate(p);
    vector_push_back(packets, p);
    if (ctx.capturing)
        ui_event(UI_NEW_DATA);
    return true;
}

static bool count_packets(iface_handle_t *handle UNUSED, unsigned char *buf,
                          uint32_t n, struct timeval *t UNUSED)
{
    if (bpf.size > 0) {
        if (bpf_run_filter(bpf, buf, n) == 0)
            return true;
    }
    ctx.packet_count++;
    return true;
}

static void handle_count_and_exit(unsigned char *buf)
{
    if (ctx.opt.load_file) {
        printf("Reading from file %s\n", ctx.filename);
        load_file(buf, count_packets);
        jomon_exit(0);
    } else {
        printf("Listening on %s\n", ctx.device);
        activate_interface(buf, count_packets);
        run();
    }
}
