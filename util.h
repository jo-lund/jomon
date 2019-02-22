#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <GeoIPCity.h>
#include "list.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct arp_info;

struct uint_string {
    uint32_t val;
    char *str;
};

static inline int cmp_val(const void *c1, const void *c2)
{
    return ((struct uint_string *) c1)->val - ((struct uint_string *) c2)->val;
}

static inline int cmp_str(const void *c1, const void *c2)
{
    return strcmp(((struct uint_string *) c1)->str, ((struct uint_string *) c2)->str);
}

// TODO: remove this
struct tm_t {
    int days;
    int hours;
    int mins;
    int secs;
};

// TODO: This should be moved to its own file. Will be used for injecting
// packets.
void serialize_arp(unsigned char *buf, struct arp_info *info);

/*
 * Get host name from addr which is in dotted-decimal format. This will send a
 * DNS request over UDP.
 */
void gethost(uint32_t addr, char *host, int hostlen);

/*
 * Concatenates fmt string to buf. Will never print passed the size of buf.
 * Expects buf to already contain a string or that buf is zeroed.
 *
 * Returns the number of bytes written.
 */
int snprintcat(char *buf, int size, char *fmt, ...);

/* Converts str to lower case */
char *strtolower(char *str);

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

/* Find index of the last character 'c' in string. Return -1 if not found */
int str_find_last(const char *str, int c);

/* Given a file with full path name, return the directory part */
char *get_directory_part(char *path);

/* Given a file with full path name, return the file part */
char *get_file_part(char *path);

/* Transforms the bytes to a human readable format, e.g. "1K", "42M" etc. */
char *format_bytes(int bytes, char *buf, int len);

/* Returns the city and country name from a GeoIPRecord, if available */
char *get_location(GeoIPRecord *record, char *buf, int len);

/* Extracts a 16 bits integer in big endian format from buf */
static inline uint16_t get_uint16be(const unsigned char *buf)
{
    return (uint16_t) buf[0] << 8 | (uint16_t) buf[1];
}

/* Extracts a 32 bits integer in big endian format from buf */
static inline uint32_t get_uint32be(const unsigned char *buf)
{
    return (uint32_t) buf[0] << 24 |
           (uint32_t) buf[1] << 16 |
           (uint32_t) buf[2] << 8 |
           (uint32_t) buf[3];
}

/* Extracts a 16 bits integer in little endian format from buf */
static inline uint16_t get_uint16le(const unsigned char *buf)
{
    return (uint16_t) buf[1] << 8 | (uint16_t) buf[0];
}

/* Extracts a 32 bits integer in little endian format from buf */
static inline uint32_t get_uint32le(const unsigned char *buf)
{
    return (uint32_t) buf[3] << 24 |
           (uint32_t) buf[2] << 16 |
           (uint32_t) buf[1] << 8 |
           (uint32_t) buf[0];
}

#endif
