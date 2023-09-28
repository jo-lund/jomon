#ifndef PRINT_PROTOCOL_H
#define PRINT_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "util.h"
#include "string.h"

#define ADDR_WIDTH 40
#define PROT_WIDTH 10
#define NUM_WIDTH 10
#define TIME_WIDTH 20
#define TBUFLEN 16

#define PRINT_NUMBER(buffer, n, i)                  \
    snprintf(buffer, n, "%-" STR(NUM_WIDTH) "u", i)
#define PRINT_TIME(buffer, n, t)                    \
    snprintf((buffer) + NUM_WIDTH, (n) - NUM_WIDTH, "%-" STR(TIME_WIDTH) "s", t)
#define PRINT_ADDRESS(buffer, n, src, dst)                              \
    snprintf((buffer) + NUM_WIDTH + TIME_WIDTH, (n) - NUM_WIDTH - TIME_WIDTH, \
             "%-" STR(ADDR_WIDTH) "s" "%-" STR(ADDR_WIDTH) "s", src, dst)
#define PRINT_PROTOCOL(buffer, n, prot)                     \
    snprintf((buffer) + NUM_WIDTH + TIME_WIDTH + 2 * ADDR_WIDTH, (n) - NUM_WIDTH - \
             TIME_WIDTH - 2 * ADDR_WIDTH, "%-" STR(PROT_WIDTH) "s", prot)
#define PRINT_INFO(buffer, n, fmt, ...) \
    snprintcat(buffer, n, fmt, ##__VA_ARGS__)
#define PRINT_LINE(buffer, n, i, t, src, dst, prot, fmt, ...)   \
    do {                                                        \
        PRINT_NUMBER(buffer, n, i);                             \
        PRINT_TIME(buffer, n, t);                               \
        PRINT_ADDRESS(buffer, n, src, dst);                     \
        PRINT_PROTOCOL(buffer, n, prot);                        \
        PRINT_INFO(buffer, n, fmt, ## __VA_ARGS__);             \
    } while (0)

struct packet;

/* write packet to buffer */
void pkt2text(char *buf, size_t size, struct packet *p);

#endif
