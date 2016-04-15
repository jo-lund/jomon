/* Network traffic monitor
 *
 * This program will monitor all incoming/outgoing network traffic and 
 * print out the speed of the download/upload. It uses the libpcap library, 
 * if available, to capture packets (http://www.tcpdump.org). On Mac OS X this
 * library will use the BSD packet filter (BPF) to interface with the network
 * device.
 *
 * The speed of the download/upload is based on the network throughput, which
 * means that the bit rate will be measured at a reference point above the 
 * datalink layer, i.e., the reference point will be the IP layer.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#ifdef MACOS
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#ifdef linux
#include <netpacket/packet.h>
#endif
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include "misc.h"
#include "error.h"
#include "interface.h"
#include "output.h"
#include "packet.h"
#include "vector.h"

linkdef rx; /* data received */
linkdef tx; /* data transmitted */
struct sockaddr_in *local_addr;
char *device = NULL;
int verbose;
int promiscuous;
int statistics;
static volatile sig_atomic_t signal_flag = 0;
static int fd; /* packet socket file descriptor */

static void print_help(char *prg);
static int init();
static void run();
static void sig_alarm(int signo);
static void sig_int(int signo);
static void finish();
static void free_mem(void *data);
static void calculate_rate();

int main(int argc, char **argv)
{
    char *prg_name = argv[0];
    int opt;
    int n;

    statistics = 0;
    promiscuous = 0;
    while ((opt = getopt(argc, argv, "i:lhvps")) != -1) {
        switch (opt) {
        case 'i':
            n = strlen(optarg);
            device = malloc(n + 1);
            strncpy(device, optarg, n);
            device[n] = '\0';
            break;
        case 'l':
            list_interfaces();
            exit(0);
            break;
        case 'p':
            promiscuous = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 's':
            statistics = 1;
            break;
        case 'h':
        default:
            print_help(prg_name);
            exit(1);
        }
    }

#ifdef linux
    fd = init();
    init_ncurses();
    create_layout();
    run(fd);
    finish();
#endif
}

void print_help(char *prg)
{
    printf("Usage: %s [-lvhp] [-i interface]\n", prg);
    printf("Options:\n");
    printf("     -i  Specify network interface\n");
    printf("     -l  List available interfaces\n");
    printf("     -p  Use promiscuous mode\n");
    printf("     -s  Show statistics page\n");
    printf("     -v  Print verbose information\n");
    printf("     -h  Print this help summary\n");
}

void sig_alarm(int signo)
{
    signal_flag = 1;
}

void sig_int(int signo)
{
    finish();
}

void finish()
{
    end_ncurses();
    vector_clear();
    free(device);
    free(local_addr);
    close(fd);
    exit(0);
}

/* Initialize device and prepare for reading */
int init()
{
    int sockfd, flag;
    struct sockaddr_ll ll_addr; /* device independent physical layer address */
    struct sigaction act, acti;

    if (!device) {
        if (!(device = get_default_interface())) {
            err_quit("Cannot find active network device\n");
        }
    }
    if (!statistics) {
        /* SOCK_RAW packet sockets include the link level header */
        if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
            err_sys("socket error");
        }
    } else {
        /* SOCK_DGRAM are cooked packets with the link level header removed */
        if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) == -1) {
            err_sys("socket error");
        }
    }

    /* use non-blocking socket */
    if ((flag = fcntl(sockfd, F_GETFL, 0)) == -1) {
        err_sys("fcntl error");
    }
    if (fcntl(sockfd, F_SETFL, flag | O_NONBLOCK) == -1) {
        err_sys("fcntl error");
    }

    setuid(getuid()); /* no need for root access anymore */
    memset(&rx, 0, sizeof(linkdef));
    memset(&tx, 0, sizeof(linkdef));
    memset(&ll_addr, 0, sizeof(ll_addr));
    ll_addr.sll_family = PF_PACKET;
    ll_addr.sll_protocol = htons(ETH_P_ALL);
    ll_addr.sll_ifindex = get_interface_index(device);

    /* only receive packets on the specified interface */
    if (bind(sockfd, (struct sockaddr *) &ll_addr, sizeof(ll_addr)) == -1) {
        err_sys("bind error");
    }

    /* set up an alarm and interrupt signal handler */
    act.sa_handler = sig_alarm;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGALRM, &act, NULL) == -1) {
        err_sys("sigaction error");
    }
    acti.sa_handler = sig_int;
    sigemptyset(&acti.sa_mask);
    if (sigaction(SIGINT, &acti, NULL) == -1) {
        err_sys("sigaction error");
    }

    local_addr = malloc(sizeof (struct sockaddr_in));
    get_local_address(device, (struct sockaddr *) local_addr);

    /* Initialize table to store packets */
    vector_init(1000, free_mem);

    return sockfd;
}

/* The main event loop */
void run(int fd)
{
    struct pollfd fds[] = {
        { fd, POLLIN },
        { STDIN_FILENO, POLLIN }
    };

    if (statistics) alarm(1);
    while (1) {
        if (signal_flag) {
            signal_flag = 0;
            alarm(1);
            calculate_rate();
        }
        if (poll(fds, 2, -1) == -1) {
            if (errno == EINTR) continue;
            err_sys("poll error");
        }
        if (fds[0].revents & POLLIN) {
            unsigned char buffer[SNAPLEN];
            size_t n;
            struct packet *p;

            p = malloc(sizeof(struct packet));
            n = read_packet(fd, buffer, SNAPLEN, p);
            if (n > ETHERNET_HDRLEN) {
                vector_push_back(p);
                print_packet(p);
            } else {
                free_mem(p);
            }
        }
        if (fds[1].revents & POLLIN) {
            get_input();
        }
        if (statistics) print_rate();
    }
}

void free_mem(void *data)
{
    struct packet *p = (struct packet *) data;

    if (p->ut == IPv4) {
        switch (p->ip.protocol) {
        case IPPROTO_UDP:
            switch (p->ip.udp.utype) {
            case DNS:
                if (p->ip.udp.dns->record) {
                    free(p->ip.udp.dns->record);
                }
                free(p->ip.udp.dns);
                break;
            case NBNS:
                if (p->ip.udp.nbns->record) {
                    free(p->ip.udp.nbns->record);
                }
                free(p->ip.udp.nbns);
                break;
            case SSDP:
                free(p->ip.udp.ssdp->str);
                free(p->ip.udp.ssdp);
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }
    }
    free(p);
}

void calculate_rate()
{
    rx.kbps = (rx.tot_bytes - rx.prev_bytes) / 1024;
    tx.kbps = (tx.tot_bytes - tx.prev_bytes) / 1024;
    rx.prev_bytes = rx.tot_bytes;
    tx.prev_bytes = tx.tot_bytes;
}
