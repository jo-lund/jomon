#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <linux/wireless.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "../system_information.h"
#include "../misc.h"

#define DEVPATH "/proc/net/dev"
#define STATUSPATH "/proc/self/status"
#define MEMPATH "/proc/meminfo"
#define CPUPATH "/proc/cpuinfo"
#define STATPATH "/proc/stat"

#define GET_VALUE(buf, i, s, l, val)            \
    do {                                        \
        i += l;                                 \
        while (isspace(buf[i])) {               \
            i++;                                \
        }                                       \
        sscanf(buf + i, s, &val);               \
    } while (0)

bool get_netstat(char *dev, struct linkdef *rx, struct linkdef *tx)
{
    FILE *fp;
    char buf[MAXLINE];
    int n;

    if (!(fp = fopen(DEVPATH, "r"))) {
        return false;
    }
    n = strlen(dev);
    while (fgets(buf, MAXLINE, fp)) {
        int i = 0;

        /* remove leading spaces */
        while (isspace(buf[i])) {
            i++;
        }
        if (strncmp(buf + i, dev, n) == 0) {
            sscanf(buf + i + n + 1,
                   "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                   &rx->tot_bytes, &rx->num_packets, &rx->errs, &rx->drop, &rx->fifo,
                   &rx->frame_cols,&rx->compressed, &rx->mc_carrier, &tx->tot_bytes,
                   &tx->num_packets, &tx->errs, &tx->drop, &tx->fifo, &tx->frame_cols,
                   &tx->mc_carrier, &tx->compressed);
            break;
        }
    }
    fclose(fp);
    return true;
}

bool get_memstat(struct memstat *mem)
{
    FILE *fp;
    char buf[MAXLINE];

    /* get memory statistics */
    if (!(fp = fopen(MEMPATH, "r"))) {
        return false;
    }
    while (fgets(buf, MAXLINE, fp)) {
        int i = 0;

        if (strncmp(buf, "MemTotal:", 9) == 0) {
            GET_VALUE(buf, i, "%lu", 9, mem->total_ram);
        } else if (strncmp(buf, "MemFree:", 8) == 0) {
            GET_VALUE(buf, i, "%lu", 8, mem->free_ram);
        } else if (strncmp(buf, "Buffers:", 8) == 0) {
            GET_VALUE(buf, i, "%lu", 8, mem->buffers);
        } else if (strncmp(buf, "Cached:", 7) == 0) {
            GET_VALUE(buf, i, "%lu", 7, mem->cached);
        }
    }
    fclose(fp);

    /* get process memory statistics */
    if (!(fp = fopen(STATUSPATH, "r"))) {
        return false;
    }
    while (fgets(buf, MAXLINE, fp)) {
        int i = 0;

        if (strncmp(buf, "Pid:", 4) == 0) {
            GET_VALUE(buf, i, "%d", 4, mem->proc.pid);
        } else if (strncmp(buf, "VmRSS:", 6) == 0) {
            GET_VALUE(buf, i, "%lu", 6, mem->proc.vm_rss);
        } else if (strncmp(buf, "VmSize:", 7) == 0) {
            GET_VALUE(buf, i, "%lu", 7, mem->proc.vm_size);
        }
    }
    fclose(fp);
    return true;
}

bool get_hwstat(struct hwstat *hw)
{
    FILE *fp;
    char buf[MAXLINE];

    if (!(fp = fopen(STATPATH, "r")))
        return false;
    while (fgets(buf, MAXLINE, fp)) {
        if (strncmp(buf, "cpu", 3) == 0) {
            if (isdigit(buf[3])) {
                hw->num_cpu++;
            }
        }
    }
    fclose(fp);
    if (!(fp = fopen(CPUPATH, "r")))
        return false;
    while (fgets(buf, MAXLINE, fp)) {
        if (strncmp(buf, "model name", 10) == 0) {
            int i = 10;
            int len;

            while (isspace(buf[i]) || buf[i] == ':') {
                i++;
            }
            len = strlen(buf + i) - 1;
            strncpy(hw->cpu_name, buf + i, CPU_MAX_NAME);
            hw->cpu_name[len] = '\0';
            break;
        }
    }
    fclose(fp);
    return true;
}

bool get_cpustat(struct cputime *cpu)
{
    FILE *fp;
    char buf[MAXLINE];
    int c = 0;

    if (!(fp = fopen(STATPATH, "r")))
        return false;
    while (fgets(buf, MAXLINE, fp)) {
        if (strncmp(buf, "cpu", 3) == 0) {
            int i = 3;

            if (isdigit(buf[i])) {
                i++;
                while (isspace(buf[i])) {
                    i++;
                }
                sscanf(buf + i, "%lu %lu %lu %lu", &cpu[c].user, &cpu[c].nice,
                       &cpu[c].system, &cpu[c].idle);
                c++;
            }
        }
    }
    fclose(fp);
    return true;
}

bool get_iwstat(char *dev, struct wireless *stat)
{
    int sockfd;
    struct iwreq iw;
    struct iw_statistics iw_stat;
    struct iw_range iw_range;

    strncpy(iw.ifr_ifrn.ifrn_name, dev, IFNAMSIZ - 1);
    iw.u.data.pointer = &iw_stat;
    iw.u.data.length = sizeof(struct iw_statistics);
    iw.u.data.flags = 0; // TODO: What are the possible values of flags?
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return false;
    }
    if ((ioctl(sockfd, SIOCGIWSTATS, &iw)) == -1) {
        close(sockfd);
        return false;
    }
    iw.u.data.pointer = &iw_range;
    iw.u.data.length = sizeof(struct iw_range);
    if ((ioctl(sockfd, SIOCGIWRANGE, &iw)) == -1) {
        close(sockfd);
        return false;
    }
    close(sockfd);
    stat->qual = iw_stat.qual.qual;
    stat->max_qual = iw_range.max_qual.qual;
    stat->level = iw_stat.qual.level;
    stat->noise = iw_stat.qual.noise;
    return true;
}
