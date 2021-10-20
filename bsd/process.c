#include <stddef.h>
#include <stdbool.h>
#include <sys/file.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <errno.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <arpa/inet.h>
#include "../process.h"
#include "../attributes.h"
#include "../hashmap.h"
#include "../decoder/tcp_analyzer.h"
#include "../monitor.h"
#include "../hash.h"

#define SIZE 512

struct process {
    char *name;
    int pid;
};

struct tcp_elem {
    uint16_t lport;
    uint16_t rport;
    uint32_t laddr;
    uint32_t raddr;
    kvaddr_t sock; /* kernel address of struct socket */
};

static hashmap_t *data_cache; /* processes keyed on file descriptor specific data */
static hashmap_t *tcp_cache;
static hashmap_t *string_table;

static char *get_name(int pid)
{
    static struct kinfo_proc proc;
    size_t len;
    char *name;
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };

    len = sizeof(proc);
    if (sysctl(mib, ARRAY_SIZE(mib), &proc, &len, NULL, 0) == -1)
        return NULL;
    if ((name = hashmap_get_key(string_table, proc.ki_comm)) == NULL) {
        name = strdup(proc.ki_comm);
        hashmap_insert(string_table, name, NULL);
    }
    return name;
}

static void get_tcp(void)
{
    void *buf;
    size_t size = 8192;
    struct xtcpcb *xtcp, *extcp;
    struct xinpcb *xin;

    buf = malloc(size);
    while (sysctlbyname("net.inet.tcp.pcblist", buf, &size, NULL, 0) == -1) {
        if (errno != ENOMEM)
            return;
        size *= 2;
        buf = realloc(buf, size);
    }
    xtcp = buf;
    extcp = (struct xtcpcb *) ((char *) buf + size - sizeof(*extcp));
    while (xtcp < extcp) {
        xtcp = (struct xtcpcb *) ((char *) xtcp + xtcp->xt_len);
        xin = &xtcp->xt_inp;
        if (xin->inp_vflag & INP_IPV4) {
            struct tcp_endpoint_v4 endp;
            struct tcp_elem *tcp;
            struct xsocket *sock;
            struct in_endpoints *in;

            sock = &xin->xi_socket;
            if (sock->xso_so == 0)
                continue;
            in = &xin->inp_inc.inc_ie;
            endp.sport = ntohs(in->ie_lport);
            endp.dport = ntohs(in->ie_fport);
            endp.src = in->ie_laddr.s_addr;
            endp.dst = in->ie_faddr.s_addr;
            if (hashmap_contains(tcp_cache, &endp))
                hashmap_remove(tcp_cache, &endp);
            tcp = malloc(sizeof(*tcp));
            tcp->laddr = endp.src;
            tcp->lport = endp.sport;
            tcp->raddr = endp.dst;
            tcp->rport = endp.dport;
            tcp->sock = sock->xso_so;
            hashmap_insert(tcp_cache, (struct tcp_endpoint_v4 *) tcp, tcp);
        }
    }
    free(buf);
}

static void update_cache(struct tcp_connection_v4 *conn, bool new_conn)
{
    if (new_conn) {
        if (conn->endp->src != ctx.local_addr->sin_addr.s_addr &&
            conn->endp->dst != ctx.local_addr->sin_addr.s_addr)
            return;
        process_load_cache();
        if (!hashmap_contains(tcp_cache, conn->endp))
            get_tcp();
    }
}

void process_init(void)
{
    data_cache = hashmap_init(SIZE, hashfnv_uint64, compare_uint);
    tcp_cache = hashmap_init(SIZE, hash_tcp_v4, compare_tcp_v4);
    string_table = hashmap_init(64, hashfnv_string, compare_string);
    hashmap_set_free_data(data_cache, free);
    hashmap_set_free_key(tcp_cache, free);
    hashmap_set_free_key(string_table, free);
    tcp_analyzer_subscribe(update_cache);
}

void process_free(void)
{
    hashmap_free(data_cache);
    hashmap_free(tcp_cache);
    hashmap_free(string_table);
    tcp_analyzer_unsubscribe(update_cache);
}

void process_load_cache(void)
{
    size_t len;
    struct xfile *xf, *p;
    int i, nfiles;
    struct process *pinfo;

    len = sizeof(*xf);
    xf = malloc(len);

    /* get the entire file table */
    while (sysctlbyname("kern.file", xf, &len, 0, 0) == -1) {
        if (errno != ENOMEM)
            return;
        len *= 2;
        xf = realloc(xf, len);
    }
    nfiles = len / sizeof(*xf);
    for (i = 0, p = xf; i < nfiles; i++, p++) {
        if (p->xf_type == DTYPE_SOCKET &&
            !hashmap_contains(data_cache, UINT_TO_PTR(p->xf_data))) {
            pinfo = malloc(sizeof(*pinfo));
            pinfo->pid = p->xf_pid;
            pinfo->name = get_name(pinfo->pid);
            hashmap_insert(data_cache, UINT_TO_PTR(p->xf_data), pinfo);
        }
    }
    free(xf);
}

void process_clear_cache(void)
{
    hashmap_clear(data_cache);
}

char *process_get_name(struct tcp_connection_v4 *conn)
{
    struct process *pinfo;
    struct tcp_elem *tcp;

    if ((tcp = hashmap_get(tcp_cache, conn->endp)) &&
        (pinfo = hashmap_get(data_cache, UINT_TO_PTR(tcp->sock))))
        return pinfo->name;
    return NULL;
}
