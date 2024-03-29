#ifndef GEOIP_H
#define GEOIP_H

#include <stdbool.h>
#include "config.h"
#include "string.h"

#ifdef HAVE_GEOIP

/* Initialize GeoIP */
void geoip_init(void);

/* Free resources connected with GeoIP */
void geoip_free(void);

/* Returns the city and country name from an IP address */
char *geoip_get_location(char *addr, char *buf, int len);

/*
 * Returns the country name from an IP address. Will allocate a new string that needs
 * to be freed by the caller.
 */
char *geoip_get_country(char *addr);

/*
 * Returns the city from an IP address. Will allocate a new string that needs
 * to be freed by the caller.
 */
char *geoip_get_city(char *addr);

/* Print library version */
void geoip_print_version(void);

#else

static inline void geoip_init(void)
{
}

static inline void geoip_free(void)
{
}

static inline char *geoip_get_location(char *addr UNUSED, char *buf, int len)
{
    strlcpy(buf, "Unknown", len);
    return buf;
}

static inline char *geoip_get_country(char *addr UNUSED)
{
    return NULL;
}

static inline char *geoip_get_city(char *addr UNUSED)
{
    return NULL;
}

static inline void geoip_print_version(void)
{
}
#endif
#endif
