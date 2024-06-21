#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <errno.h>
#include <stdio.h>
#include <pwd.h>
#include "process.h"
#include "misc.h"
#include "hash.h"
#include "decoder/tcp_analyzer.h"
#include "list.h"
#include "wrapper.h"
#include "debug.h"

/*
 * General algorithm to get the process related to the specific connection:
 *
 * 1. Traverse /proc/pid
 * 2. For each pid traverse /proc/pid/fd/
 * 3. For each fd call readlink, check if it's a socket and extract inode
 * 4.
 *   a. Alternative 1
 *      For each inode open /proc/net/tcp and check if the kernel TCP table
 *      has an entry for the inode.
 *   b. Alternative 2
 *      Initialize a netlink socket to query information about sockets, request
 *      to get a list of TCP sockets and read the response which should contain,
 *      among other things, the inode.
 * 5. If there is a match, open /proc/pid/cmdline to get the process name.
 */

#define PROC "/proc"
#define FD "fd"
#define CMDLINE "cmdline"
#define SOCKET "socket:["
#define SIZE 512

struct tcp_elem {
    uint16_t lport;
    uint16_t rport;
    uint32_t laddr;
    uint32_t raddr;
    uint32_t inode;
    uint32_t uid;
};

static hashmap_t *inode_cache; /* processes keyed on inode */
static hashmap_t *proc_cache; /* processes keyed on pid */
static hashmap_t *tcp_cache;
static hashmap_t *proc_conn; /* processes with open connections */
static int nl_sockfd;

static void load_cache(void);

static void free_process(void *p)
{
    struct process *proc = (struct process *) p;

    free(proc->name);
    if (proc->user)
        free(proc->user);
    if (proc->conn)
        list_free(proc->conn, NULL);
    free(proc);
}

static char *get_name(int pid)
{
    char cmdline[MAXPATH];
    FILE *fp;

    snprintf(cmdline, MAXPATH, "/proc/%d/cmdline", pid);
    if ((fp = fopen(cmdline, "r")) == NULL)
        return NULL;
    if (fgets(cmdline, MAXPATH, fp) == NULL) {
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    return xstrdup(cmdline);
}

char *get_username(uint32_t uid)
{
    struct passwd *pw;

    if ((pw = getpwuid(uid)) == NULL)
        return NULL;
    return xstrdup(pw->pw_name);
}

static void load_cache(void)
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
            char fd[SIZE];

            snprintf(fd, SIZE, "%s/%s/%s", PROC, dp->d_name, FD);
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
                    int pid;

                    if ((inode = strtol(slink + sn, NULL, 10)) == 0)
                        continue;
                    if (!hashmap_get(inode_cache, UINT_TO_PTR(inode))) {
                        pid = strtol(dp->d_name, NULL, 10);
                        if ((pinfo = hashmap_get(proc_cache, INT_TO_PTR(pid))) == NULL) {
                            pinfo = xcalloc(1, sizeof(struct process));
                            pinfo->pid = pid;
                            pinfo->name = get_name(pinfo->pid);
                            hashmap_insert(proc_cache, INT_TO_PTR(pid), pinfo);
                        }
                        hashmap_insert(inode_cache, UINT_TO_PTR(inode), pinfo);
                    }
                }
            }
            closedir(dfd2);
        }
    }
    closedir(dfd);
}

static bool send_netlink_msg(void)
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

static bool read_netlink_msg(void)
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

        if ((len = recvmsg(nl_sockfd, &msg, 0)) < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            DEBUG("read_netlink_msg error: %s (%d)", strerror(errno), errno);
            return false;
        }
        if (len == 0) {
            DEBUG("read_netlink_msg EOF", strerror(errno), errno);
            return false;
        }
        for (struct nlmsghdr *nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len)) {
            struct tcp_elem *old, *tcp;
            struct tcp_endpoint_v4 endp;
            struct process *pinfo;

            if (nh->nlmsg_type == NLMSG_DONE)
                return true;
            if (nh->nlmsg_type == NLMSG_ERROR)
                return false;
            diag_msg = (struct inet_diag_msg *) NLMSG_DATA(nh);
            if (diag_msg->idiag_inode == 0)
                continue;
            endp.src = diag_msg->id.idiag_src[0];
            endp.sport = ntohs(diag_msg->id.idiag_sport);
            endp.dst = diag_msg->id.idiag_dst[0];
            endp.dport = ntohs(diag_msg->id.idiag_dport);
            if ((old = hashmap_get(tcp_cache, &endp))) {
                if (diag_msg->idiag_inode != old->inode)
                    hashmap_remove(tcp_cache, &endp);
                else
                    continue;
            }
            tcp = xmalloc(sizeof(*tcp));
            tcp->laddr = diag_msg->id.idiag_src[0];
            tcp->lport = ntohs(diag_msg->id.idiag_sport);
            tcp->raddr = diag_msg->id.idiag_dst[0];
            tcp->rport = ntohs(diag_msg->id.idiag_dport);
            tcp->inode = diag_msg->idiag_inode;
            tcp->uid = diag_msg->idiag_uid;
            hashmap_insert(tcp_cache, (struct tcp_endpoint_v4 *) tcp, tcp);
            if ((pinfo = hashmap_get(inode_cache, UINT_TO_PTR(tcp->inode)))) {
                if (!pinfo->user)
                    pinfo->user = get_username(tcp->uid);
            }
        }
    }
    return false;
}

static void update_cache(struct tcp_connection_v4 *conn, bool new_conn)
{
    if (new_conn) {
        struct tcp_elem *tcp;
        struct process *pinfo;

        if (conn->endp->src != ctx.local_addr->sin_addr.s_addr &&
            conn->endp->dst != ctx.local_addr->sin_addr.s_addr)
            return;
        load_cache();
        if ((tcp = hashmap_get(tcp_cache, conn->endp)) == NULL) {
            if (send_netlink_msg())
                read_netlink_msg();
        }
        if (!tcp && (tcp = hashmap_get(tcp_cache, conn->endp)) == NULL)
            return;
        if ((pinfo = hashmap_get(inode_cache, UINT_TO_PTR(tcp->inode)))) {
            if (!pinfo->conn)
                pinfo->conn = list_init(NULL);
            list_push_back(pinfo->conn, conn);
        }
    }
}

static bool netlink_init(void)
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

hashmap_t *process_get_processes(void)
{
    const hashmap_iterator *it;
    struct process *p;

    hashmap_clear(proc_conn);
    HASHMAP_FOREACH(tcp_cache, it) {
        if ((p = hashmap_get(inode_cache, UINT_TO_PTR(((struct tcp_elem *) it->data)->inode))) && p->conn)
            hashmap_insert(proc_conn, INT_TO_PTR(p->pid), p);
    }
    return proc_conn;
}

void process_init(void)
{
    inode_cache = hashmap_init(SIZE, hashfnv_uint32, compare_uint);
    tcp_cache = hashmap_init(SIZE, hash_tcp_v4, compare_tcp_v4);
    proc_cache = hashmap_init(64, NULL, NULL);
    proc_conn = hashmap_init(16, NULL, NULL);
    hashmap_set_free_data(proc_cache, free_process);
    hashmap_set_free_key(tcp_cache, free);
    tcp_analyzer_subscribe(update_cache);
    netlink_init();
}

void process_load_cache(void)
{
    load_cache();
}

void process_clear_cache(void)
{
    hashmap_clear(inode_cache);
    hashmap_clear(tcp_cache);
    hashmap_clear(proc_cache);
}

void process_free(void)
{
    hashmap_free(inode_cache);
    hashmap_free(tcp_cache);
    hashmap_free(proc_cache);
    hashmap_free(proc_conn);
    tcp_analyzer_unsubscribe(update_cache);
    close(nl_sockfd);
}
