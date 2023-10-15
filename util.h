#ifndef UTIL_H
#define UTIL_H

#include <string.h>
#include <stdint.h>
#include "list.h"

/*
 * Subtracts the offset of a structure's member from its address to get the
 * address of the containing structure.
 *
 * ptr    - The pointer to the member
 * type   - The type of the struct this is embedded in
 * member - The name of the member within the struct
 */
#define CONTAINER_OF(ptr, type, member) ({                        \
            const typeof(((type *) 0)->member) *_mptr = (ptr);    \
            (type *) ((char *) _mptr - offsetof(type, member));})

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* hardware address length (format aa:bb:cc:dd:ee:ff) */
#define HW_ADDRSTRLEN 18
#define HWSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define HW2STR(x) (x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5]
#define HW_ADDR_NTOP(dst, src) \
    snprintf(dst, HW_ADDRSTRLEN, HWSTR, HW2STR(src))

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

#define _STR(x) #x
#define STR(x) _STR(x)

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
 * Extract a 16 bits integer in big endian format from buf without incrementing the buffer
 */
static inline uint16_t get_uint16be(const unsigned char *buf)
{
    return (uint16_t) buf[0] << 8 | (uint16_t) buf[1];
}

/*
 * Extract a 32 bits integer in big endian format from buf without incrementing the buffer
 */
static inline uint32_t get_uint32be(const unsigned char *buf)
{
    return (uint32_t) buf[0] << 24 |
           (uint32_t) buf[1] << 16 |
           (uint32_t) buf[2] << 8 |
           (uint32_t) buf[3];
}

/*
 * Extract a 64 bits integer in big endian format from buf without incrementing the buffer
 */
static inline uint64_t get_uint64be(const unsigned char *buf)
{
    return (uint64_t) buf[0] << 56 |
           (uint64_t) buf[1] << 48 |
           (uint64_t) buf[2] << 40 |
           (uint64_t) buf[3] << 32 |
           (uint64_t) buf[4] << 24 |
           (uint64_t) buf[5] << 16 |
           (uint64_t) buf[6] << 8 |
           (uint64_t) buf[7];
}

/*
 * Extract a 16 bits integer in little endian format from buf without incrementing the buffer
 */
static inline uint16_t get_uint16le(const unsigned char *buf)
{
    return (uint16_t) buf[1] << 8 | (uint16_t) buf[0];
}

/*
 * Extract a 32 bits integer in little endian format from buf without incrementing the buffer
 */
static inline uint32_t get_uint32le(const unsigned char *buf)
{
    return (uint32_t) buf[3] << 24 |
           (uint32_t) buf[2] << 16 |
           (uint32_t) buf[1] << 8 |
           (uint32_t) buf[0];
}

/*
 * Extract a 64 bits integer in little endian format from buf without incrementing the buffer
 */
static inline uint64_t get_uint64le(const unsigned char *buf)
{
    return (uint64_t) buf[7] << 56 |
           (uint64_t) buf[6] << 48 |
           (uint64_t) buf[5] << 40 |
           (uint64_t) buf[4] << 32 |
           (uint64_t) buf[3] << 24 |
           (uint64_t) buf[2] << 16 |
           (uint64_t) buf[1] << 8 |
           (uint64_t) buf[0];
}

/*
 * Extract a 16 bits integer in big endian format from buf and increments the buffer
 */
static inline uint16_t read_uint16be(unsigned char **buf)
{
    uint16_t val;

    val = (uint16_t) *(*buf)++ << 8;
    val |= (uint16_t) *(*buf)++;
    return val;
}

/*
 * Extract a 32 bits integer in big endian format from buf and increments the buffer
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
 * Extract a 64 bits integer in big endian format from buf and increments the buffer
 */
static inline uint64_t read_uint64be(unsigned char **buf)
{
    uint64_t val;

    val = (uint64_t) *(*buf)++ << 56;
    val |= (uint64_t) *(*buf)++ << 48;
    val |= (uint64_t) *(*buf)++ << 40;
    val |= (uint64_t) *(*buf)++ << 32;
    val |= (uint64_t) *(*buf)++ << 24;
    val |= (uint64_t) *(*buf)++ << 16;
    val |= (uint64_t) *(*buf)++ << 8;
    val |= (uint64_t) *(*buf)++;
    return val;
}

/*
 * Extract a 16 bits integer in little endian format from buf and increments the buffer
 */
static inline uint16_t read_uint16le(unsigned char **buf)
{
    uint16_t val;

    val = (uint16_t) *(*buf)++;
    val |= (uint16_t) *(*buf)++ << 8;
    return val;
}

/*
 * Extract a 32 bits integer in little endian format from buf and increments the buffer
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

/*
 * Extract a 64 bits integer in little endian format from buf and increments the buffer
 */
static inline uint64_t read_uint64le(unsigned char **buf)
{
    uint64_t val;

    val = (uint64_t) *(*buf)++;
    val |= (uint64_t) *(*buf)++ << 8;
    val |= (uint64_t) *(*buf)++ << 16;
    val |= (uint64_t) *(*buf)++ << 24;
    val |= (uint64_t) *(*buf)++ << 32;
    val |= (uint64_t) *(*buf)++ << 40;
    val |= (uint64_t) *(*buf)++ << 48;
    val |= (uint64_t) *(*buf)++ << 56;
    return val;
}

/* Compute the least power of two greater than or equal to x */
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

static inline int popcnt(uint32_t x)
{
#ifdef __builtin_popcount
    return __builtin_popcount(x);
#else
    int c = 0;

    while (x) {
        x &= x - 1;
        c++;
    }
    return c;
#endif
}

#endif
