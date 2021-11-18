#ifndef SYSTEM_INFORMATION_H
#define SYSTEM_INFORMATION_H

#include <stdbool.h>
#include <stdint.h>

#define CPU_MAX_NAME 128

/* RX/TX statistics */
struct linkdef {
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
};

struct memstat {
    unsigned long total_ram;
    unsigned long free_ram;
    unsigned long buffers;
    unsigned long cached;
    struct process {
        unsigned long vm_rss;
        unsigned long vm_size;
        int pid;
    } proc;
};

struct hwstat {
    int num_cpu;
    char cpu_name[CPU_MAX_NAME];
};

struct cputime {
    unsigned long user;
    unsigned long nice;
    unsigned long system;
    unsigned long idle;
};

struct wireless {
    uint8_t qual;
    uint8_t max_qual;
    uint8_t level;
    uint8_t noise;
};

/* get network device status information */
bool get_netstat(char *dev, struct linkdef *rx, struct linkdef *tx);

/* get memory usage information  */
bool get_memstat(struct memstat *mem);

/* get cpu and hardware information */
bool get_hwstat(struct hwstat *hw);

/* get cpu statistics */
bool get_cpustat(struct cputime *cpu);

/* get wireless statistics */
bool get_iwstat(char *dev, struct wireless *stat);

#endif
