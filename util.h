#ifndef UTIL_H
#define UTIL_H

#include <string.h>
#include <stdint.h>
#include "list.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* hardware address length (format aa:bb:cc:dd:ee:ff) */
#define HW_ADDRSTRLEN 18

#define HW_ADDR_NTOP(dst, src)                                          \
    snprintf(dst, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",       \
             (src)[0], (src)[1], (src)[2], (src)[3], (src)[4], (src)[5])

/* store an unsigned integer into a pointer */
#define UINT_TO_PTR(i) ((void *) (uintptr_t) (i))

/* extract an unsigned integer from a pointer */
#define PTR_TO_UINT(i) ((uintptr_t) (i))

/* store an integer into a pointer */
#define INT_TO_PTR(i) ((void *) (intptr_t) (i))

/* extract an integer from a pointer */
#define PTR_TO_INT(i) ((intptr_t) (i))

#ifndef MAX
#define MAX(a, b) ({ typeof(a) _a = (a), _b = (b); _a > _b ? _a : _b; })
#endif

struct timeval;
struct timespec;

// TODO: remove this
struct tm_t {
    int days;
    int hours;
    int mins;
    int secs;
};

/*
 * Get host name from addr which is in dotted-decimal format. This will send a
 * DNS request over UDP.
 */
void gethost(uint32_t addr, char *host, int hostlen);

/*
 * Converts seconds to number of days, hours, minutes and seconds
 */
struct tm_t get_time(uint32_t num_secs);

/*
 * Converts the tm_t struct to a string of the form:
 * "x days, x hours, x minutes, x seconds"
 */
void time_ntop(struct tm_t *time, char *result, int len);

/* TODO: format should be made configurable */
char *format_timeval(struct timeval *t, char *buf, int n);

/* TODO: format should be made configurable */
char *format_timespec(struct timespec *t, char *buf, int n);

/*
 * Converts number of milliseconds since midnight UT to a string representation
 * in the form h:m:s.ms
 */
char *get_time_from_ms_ut(uint32_t ms, char *buf, int n);

/* Given a file with full path name, return the directory part */
char *get_directory_part(char *path);

/* Given a file with full path name, return the file part */
char *get_file_part(char *path);

/* Transforms the bytes to a human readable format, e.g. "1K", "42M" etc. */
char *format_bytes(uint64_t bytes, char *buf, int len);

/*
 * Returns the canonical textual representation of a UUID. Memory is allocated for
 * the string that must be freed by the caller.
 */
char *uuid_format(uint8_t *uuid);

/*
 * Extracts a 16 bits integer in big endian format from buf without incrementing the buffer
 */
static inline uint16_t get_uint16be(const unsigned char *buf)
{
    return (uint16_t) buf[0] << 8 | (uint16_t) buf[1];
}

/*
 * Extracts a 32 bits integer in big endian format from buf without incrementing the buffer
 */
static inline uint32_t get_uint32be(const unsigned char *buf)
{
    return (uint32_t) buf[0] << 24 |
           (uint32_t) buf[1] << 16 |
           (uint32_t) buf[2] << 8 |
           (uint32_t) buf[3];
}

/*
 * Extracts a 16 bits integer in little endian format from buf without incrementing the buffer
 */
static inline uint16_t get_uint16le(const unsigned char *buf)
{
    return (uint16_t) buf[1] << 8 | (uint16_t) buf[0];
}

/*
 * Extracts a 32 bits integer in little endian format from buf without incrementing the buffer
 */
static inline uint32_t get_uint32le(const unsigned char *buf)
{
    return (uint32_t) buf[3] << 24 |
           (uint32_t) buf[2] << 16 |
           (uint32_t) buf[1] << 8 |
           (uint32_t) buf[0];
}

/*
 * Extracts a 16 bits integer in big endian format from buf and increments the buffer
 */
static inline uint16_t read_uint16be(unsigned char **buf)
{
    uint16_t val;

    val = (uint16_t) *(*buf)++ << 8;
    val |= (uint16_t) *(*buf)++;
    return val;
}

/*
 * Extracts a 32 bits integer in big endian format from buf and increments the buffer
 */
static inline uint32_t read_uint32be(unsigned char **buf)
{
    uint32_t val;

    val = (uint32_t) *(*buf)++ << 24;
    val |= (uint32_t) *(*buf)++ << 16;
    val |= (uint32_t) *(*buf)++ << 8;
    val |= (uint32_t) *(*buf)++;
    return val;
}

/*
 * Extracts a 16 bits integer in little endian format from buf and increments the buffer
 */
static inline uint16_t read_uint16le(unsigned char **buf)
{
    uint16_t val;

    val = (uint16_t) *(*buf)++;
    val |= (uint16_t) *(*buf)++ << 8;
    return val;
}

/*
 * Extracts a 32 bits integer in little endian format from buf and increments the buffer
 */
static inline uint32_t read_uint32le(unsigned char **buf)
{
    uint32_t val;

    val = (uint32_t) *(*buf)++;
    val |= (uint32_t) *(*buf)++ << 8;
    val |= (uint32_t) *(*buf)++ << 16;
    val |= (uint32_t) *(*buf)++ << 24;
    return val;
}

/* Computes the least power of two greater than or equal to x */
static inline unsigned int clp2(unsigned int x)
{
    x--;
    x = x | (x >> 1);
    x = x | (x >> 2);
    x = x | (x >> 4);
    x = x | (x >> 8);
    x = x | (x >> 16);
    return x + 1;
}


#endif
