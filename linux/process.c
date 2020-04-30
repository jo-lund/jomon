#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <errno.h>
#include "../process.h"
#include "../misc.h"
#include "../util.h"
#include "../hash.h"
#include "../decoder/tcp_analyzer.h"

#define PROC "/proc"
#define FD "fd"
#define CMDLINE "cmdline"
#define SOCKET "socket:["
#define TCPPATH "/proc/net/tcp"
#define SIZE 512

struct process {
    char *name;
    int pid;
    unsigned inode;
};

struct tcp_elem {
    uint16_t lport;
    uint16_t rport;
    uint32_t laddr;
    uint32_t raddr;
    uint32_t inode;
};

static hashmap_t *inode_cache; /* processes keyed on inode */
static hashmap_t *tcp_cache;
static hashmap_t *string_table;
static int nl_sockfd;

static void load_cache();

static char *get_name(int pid)
{
    char cmdline[MAXPATH];
    char tmp[1024];
    FILE *fp;
    char *name;
    size_t n;

    snprintf(cmdline, MAXPATH, "/proc/%d/cmdline", pid);
    if ((fp = fopen(cmdline, "r")) == NULL)
        return NULL;
    if (fgets(tmp, MAXPATH, fp) == NULL) {
        fclose(fp);
        return NULL;
    }
    if ((name = hashmap_get_key(string_table, tmp)) == NULL) {
        n = strlen(tmp);
        name = malloc(n + 1);
        strncpy(name, tmp, n);
        name[n] = '\0';
        hashmap_insert(string_table, name, NULL);
    }
    return name;
}

static bool parse_tcp()
{
    FILE *fp;
    char buf[MAXLINE];
    unsigned int i = 0;
    bool ret = false;
    char laddr[64];
    char raddr[64];
    int lport;
    int rport;
    uint32_t inode;
    struct tcp_elem *tcp;
    struct tcp_elem *old;
    struct tcp_endpoint_v4 endp;

    if (!(fp = fopen(TCPPATH, "r")))
        return false;
    while (fgets(buf, MAXLINE, fp)) {
        while (isspace(buf[i]))
            i++;
        if (!isdigit(buf[i]))
            continue;
        if (sscanf(buf + i, "%*u: %32[A-Fa-f0-9]:%x %32[A-Fa-f0-9]:%x %*x %*u:%*u %*x:%*x %*u %*u %*u %u",
                   laddr, &lport, raddr, &rport, &inode) != 5) {
            break;
        }
        if (strlen(laddr) > 8 || strlen(raddr) > 8) /* TODO: support IPv6 */
            continue;
        endp.src = strtol(laddr, NULL, 16);
        endp.dst = strtol(raddr, NULL, 16);
        endp.src_port = lport;
        endp.dst_port = rport;
        if ((old = hashmap_get(tcp_cache, &endp))) {
            if (inode != old->inode)
                hashmap_remove(tcp_cache, &endp);
            else
                continue;
        }
        tcp = malloc(sizeof(*tcp));
        tcp->laddr = strtol(laddr, NULL, 16);
        tcp->raddr = strtol(raddr, NULL, 16);
        tcp->lport = lport;
        tcp->rport = rport;
        tcp->inode = inode;
        hashmap_insert(tcp_cache, (struct tcp_connection_v4 *) tcp, tcp);
    }
    fclose(fp);
    return ret;
}

/*
 * 1. Traverses /proc/pid
 * 2. For each pid traverses /proc/pid/fd/
 * 3. For each fd calls readlink, checks if it's a socket and extracts inode
 * 4. For each inode opens /proc/net/tcp and checks if the kernel TCP table
 *    has an entry for the inode.
 * 5. If there is a match, opens /proc/pid/cmdline to get the process name.
 */
static void load_cache()
{
    DIR *dfd;
    struct dirent *dp;
    unsigned int inode = 0;

    if ((dfd = opendir(PROC)) == NULL)
        return;
    while ((dp = readdir(dfd)) != NULL) {
        char *t = dp->d_name;

        while (*t != '\0') {
            if (!isdigit(*t))
                break;
            t++;
        }
        if (*t)
            continue;
        if (dp->d_type == DT_DIR) {
            DIR *dfd2;
            struct dirent *dp2;
            char fd[MAXPATH];

            snprintf(fd, MAXPATH, "%s/%s/%s", PROC, dp->d_name, FD);
            if ((dfd2 = opendir(fd)) == NULL) {
                closedir(dfd);
                return;
            }
            while ((dp2 = readdir(dfd2)) != NULL) {
                ssize_t linkn;
                size_t sn;
                char path[MAXPATH];
                char slink[MAXPATH];

                snprintf(path, MAXPATH, "%s/%s", fd, dp2->d_name);
                linkn = readlink(path, slink, MAXPATH);
                if (linkn == -1) {
                    continue;
                }
                slink[linkn] = '\0';
                sn = strlen(SOCKET);
                if (strncmp(SOCKET, slink, sn) == 0) {
                    struct process *pinfo;

                    if ((inode = strtol(slink + sn, NULL, 10)) == 0)
                        continue;
                    if (!hashmap_get(inode_cache, UINT_TO_PTR(inode))) {
                        pinfo = calloc(1, sizeof(struct process));
                        pinfo->pid = strtol(dp->d_name, NULL, 10);
                        pinfo->inode = inode;
                        pinfo->name = get_name(pinfo->pid);
                        hashmap_insert(inode_cache, UINT_TO_PTR(inode), pinfo);
                    }
                }
            }
            closedir(dfd2);
        }
    }
    closedir(dfd);
}

static bool send_netlink_msg()
{
    struct msghdr msg;
    struct iovec iov[2];
    struct sockaddr_nl nl_addr = {
        .nl_family = AF_NETLINK
    };
    struct inet_diag_req_v2 req = {
        .sdiag_family = AF_INET,
        .sdiag_protocol = IPPROTO_TCP,
        .idiag_states = 0xfff
    };
    struct nlmsghdr nlh = {
        .nlmsg_type = SOCK_DIAG_BY_FAMILY,
        .nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
        .nlmsg_len = NLMSG_LENGTH(sizeof(req))
    };

    memset(&msg, 0, sizeof(msg));
    iov[0].iov_base = (void *) &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = (void *) &req;
    iov[1].iov_len = sizeof(req);
    msg.msg_name = (void*) &nl_addr;
    msg.msg_namelen = sizeof(nl_addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    return sendmsg(nl_sockfd, &msg, 0) > 0;
}

static bool read_netlink_msg()
{
    char buf[32768]; // TODO: Check size
    struct inet_diag_msg *diag_msg;
    struct sockaddr_nl nl_addr = {
        .nl_family = AF_NETLINK
    };
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = sizeof(buf)
    };
    struct msghdr msg = {
        .msg_name = (void *) &nl_addr,
        .msg_namelen = sizeof(nl_addr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    while (1) {
        ssize_t len;

        while ((len = recvmsg(nl_sockfd, &msg, 0)) < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
        }
        if (len < 0)
            return false;
        for (struct nlmsghdr *nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len)) {
            struct tcp_elem *old;
            struct tcp_endpoint_v4 endp;

            if (nh->nlmsg_type == NLMSG_DONE)
                return true;
            if (nh->nlmsg_type == NLMSG_ERROR)
                return false;
            diag_msg = (struct inet_diag_msg *) NLMSG_DATA(nh);
            if (diag_msg->idiag_inode == 0)
                continue;
            endp.src = diag_msg->id.idiag_src[0];
            endp.src_port = diag_msg->id.idiag_sport;
            endp.dst = diag_msg->id.idiag_dst[0];
            endp.dst_port = diag_msg->id.idiag_dport;
            if ((old = hashmap_get(tcp_cache, &endp))) {
                if (diag_msg->idiag_inode != old->inode)
                    hashmap_remove(tcp_cache, &endp);
                else
                    continue;
            }
            struct tcp_elem *tcp = malloc(sizeof(*tcp));
            tcp->laddr = diag_msg->id.idiag_src[0];
            tcp->lport = diag_msg->id.idiag_sport;
            tcp->raddr = diag_msg->id.idiag_dst[0];
            tcp->rport = diag_msg->id.idiag_dport;
            tcp->inode = diag_msg->idiag_inode;
            hashmap_insert(tcp_cache, (struct tcp_endpoint_v4 *) tcp, tcp);
        }
    }
    return false;
}

static void update_cache(struct tcp_connection_v4 *conn, bool new_conn)
{
    if (new_conn) {
        if (conn->endp->src != ctx.local_addr->sin_addr.s_addr &&
            conn->endp->dst != ctx.local_addr->sin_addr.s_addr)
            return;
        load_cache();
        if (!hashmap_contains(tcp_cache, conn->endp)) {
            if (!(send_netlink_msg() && read_netlink_msg()))
                parse_tcp();
        }
    }
}

static bool netlink_init()
{
    struct sockaddr_nl nl_addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = getpid()
    };

    if ((nl_sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) < 0)
        return false;
    bind(nl_sockfd, (struct sockaddr *) &nl_addr, sizeof(nl_addr));
    return true;
}

char *process_get_name(struct tcp_connection_v4 *conn)
{
    struct process *pinfo;
    struct tcp_elem *tcp;

    if ((tcp = hashmap_get(tcp_cache, conn->endp)) &&
        (pinfo = hashmap_get(inode_cache, UINT_TO_PTR(tcp->inode))))
        return pinfo->name;
    return NULL;
}

void process_init()
{
    inode_cache = hashmap_init(SIZE, hash_uint32, compare_uint);
    tcp_cache = hashmap_init(SIZE, hash_tcp_v4, compare_tcp_v4);
    string_table = hashmap_init(64, hash_string, compare_string);
    hashmap_set_free_data(inode_cache, free);
    hashmap_set_free_key(tcp_cache, free);
    hashmap_set_free_key(string_table, free);
    tcp_analyzer_subscribe(update_cache);
    netlink_init();
}

void process_load_cache()
{
    load_cache();
}

void process_clear_cache()
{
    hashmap_clear(inode_cache);
}

void process_free()
{
    hashmap_free(inode_cache);
    hashmap_free(tcp_cache);
    hashmap_free(string_table);
    tcp_analyzer_unsubscribe(update_cache);
    close(nl_sockfd);
}
