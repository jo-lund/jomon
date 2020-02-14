#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
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
    uint16_t port;
    unsigned inode;
};

struct tcp_table {
    uint32_t laddr;
    uint32_t lport;
    uint32_t raddr;
    uint32_t rport;
    uint32_t inode;
};

typedef bool (*handle_tcp_entry)(struct tcp_table *tcp, void **data);

static hashmap_t *inode_cache; /* list of processes keyed on inode */
static hashmap_t *process_cache; /* list of processes keyed on connection address */

static void load_cache();

static void free_process(void *data)
{
    struct process *proc = data;

    if (proc) {
        free(proc->name);
        free(proc);
    }
}

static bool get_name(char *name, int pid)
{
    char cmdline[MAXPATH];
    FILE *fp;

    snprintf(cmdline, MAXPATH, "/proc/%d/cmdline", pid);
    if ((fp = fopen(cmdline, "r")) == NULL)
        return false;
    if (fgets(name, MAXPATH, fp) == NULL) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

static bool init_proc(struct tcp_table *tcp, void **data)
{
    char name[MAXPATH];
    struct process *pinfo = *(struct process **) data;

    if (pinfo->inode == tcp->inode && get_name(name, pinfo->pid)) {
        size_t n = strlen(name);

        pinfo->name = malloc(n + 1);
        strncpy(pinfo->name, name, n);
        pinfo->name[n] = '\0';
        pinfo->port = tcp->lport;
        return true;
    }
    return false;
}

static bool check_conn(struct tcp_table *tcp, void **data)
{
    struct tcp_endpoint_v4 *endp = *(struct tcp_endpoint_v4 **) data;

    if ((endp->src == tcp->laddr && endp->src_port == tcp->lport &&
         endp->dst == tcp->raddr && endp->dst_port == tcp->rport) ||
        (endp->dst == tcp->laddr && endp->dst_port == tcp->lport &&
         endp->src == tcp->raddr && endp->src_port == tcp->rport)) {
        *(uint32_t **) data = UINT_TO_PTR(tcp->inode);
        return true;
    }
    return false;
}

static bool parse_tcp(handle_tcp_entry fcn, void **data)
{
    FILE *fp;
    char buf[MAXLINE];
    unsigned int i = 0;
    struct tcp_table tcp;
    bool ret = false;
    char laddr[64];
    char raddr[64];

    if (!(fp = fopen(TCPPATH, "r")))
        return false;
    while (fgets(buf, MAXLINE, fp)) {
        while (isspace(buf[i]))
            i++;
        if (!isdigit(buf[i]))
            continue;
        if (sscanf(buf + i, "%*u: %32[A-Fa-f0-9]:%x %32[A-Fa-f0-9]:%x %*x %*u:%*u %*x:%*x %*u %*u %*u %u",
                   laddr, &tcp.lport, raddr, &tcp.rport, &tcp.inode) != 5)
            goto done;
        if (strlen(laddr) > 8 || strlen(raddr) > 8) /* TODO: support IPv6 */
            continue;
        tcp.laddr = strtol(laddr, NULL, 16);
        tcp.raddr = strtol(raddr, NULL, 16);
        if (fcn(&tcp, data)) {
            ret = true;
            goto done;
        }
    }
done:
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
        if (*t) {
            continue;
        }
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
                        pinfo = malloc(sizeof(struct process));
                        pinfo->pid = strtol(dp->d_name, NULL, 10);
                        pinfo->name = NULL;
                        pinfo->port = 0;
                        pinfo->inode = inode;
                        parse_tcp(init_proc, (void **) &pinfo);
                        hashmap_insert(inode_cache, UINT_TO_PTR(inode), pinfo);
                    }
                }
            }
            closedir(dfd2);
        }
    }
    closedir(dfd);
}

/* TODO: what about different network namespaces? */
static void update_cache(struct tcp_connection_v4 *conn, bool new_conn)
{
    if (new_conn) {
        void *data;
        struct process *pinfo;

        if (conn->endp->src != ctx.local_addr->sin_addr.s_addr &&
            conn->endp->dst != ctx.local_addr->sin_addr.s_addr)
            return;

        data = conn->endp;
        if (parse_tcp(check_conn, &data)) {
            if ((pinfo = hashmap_get(inode_cache, data)))
                hashmap_insert(process_cache, conn->endp, pinfo);
            else {
                load_cache(); // TODO: Don't do this too often.
                if ((pinfo = hashmap_get(inode_cache, data)))
                    hashmap_insert(process_cache, conn->endp, pinfo);
            }
        }
    }
}

char *process_get_name(struct tcp_connection_v4 *conn)
{
    struct process *pinfo;

    if ((pinfo = hashmap_get(process_cache, conn->endp)))
        return pinfo->name;
    return NULL;
}

void process_init()
{
    inode_cache = hashmap_init(SIZE, hash_uint32, compare_uint);
    hashmap_set_free_data(inode_cache, free_process);
    process_cache = hashmap_init(SIZE, hash_tcp_v4, compare_tcp_v4);
    tcp_analyzer_subscribe(update_cache);
}

void process_load_cache()
{
    load_cache();
}

void process_clear_cache()
{
    hashmap_clear(inode_cache);
    hashmap_clear(process_cache);
}

void process_free()
{
    hashmap_free(inode_cache);
    hashmap_free(process_cache);
    tcp_analyzer_unsubscribe(update_cache);
}
