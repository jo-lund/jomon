#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include "list.h"

struct arp_info;

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
 * TODO: use localtime & strftime
 */
struct tm_t get_time(uint32_t num_secs);

/*
 * Converts the tm_t struct to a string of the form:
 * "x days, x hours, x minutes, x seconds"
 * TODO: use localtime & strftime
 */
void time_ntop(struct tm_t *time, char *result, int len);

/* TODO: format should be made configurable */
char *format_timeval(struct timeval *t, char *buf, int n);

/* TODO: format should be made configurable */
char *format_timespec(struct timespec *t, char *buf, int n);

/* Find index of the first character 'c' in string. Return -1 if not found */
int str_find_first(const char *str, char c);

/* Find index of the last character 'c' in string. Return -1 if not found */
int str_find_last(const char *str, char c);

/* Given a file with full path name, return the directory part */
char *get_directory_part(char *path);

/* Given a file with full path name, return the file part */
char *get_file_part(char *path);

/* Extracts a 16 bits integer in big endian format from buf */
uint16_t get_uint16be(const unsigned char *buf);

/* Extracts a 32 bits integer in big endian format from buf */
uint32_t get_uint32be(const unsigned char *buf);

/* Extracts a 16 bits integer in little endian format from buf */
uint16_t get_uint16le(const unsigned char *buf);

/* Extracts a 32 bits integer in little endian format from buf */
uint32_t get_uint32le(const unsigned char *buf);

/* Transforms the bytes to a human readable format, e.g. "1K", "42M" etc. */
char *format_bytes(int bytes, char *buf, int len);

#endif
