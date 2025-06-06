#include <GeoIP.h>
#include <GeoIPCity.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include "geoip.h"
#include "config.h"
#include "string.h"
#include "wrapper.h"
#include "debug.h"

#define GEOIP_WARNING "Warning: Could not open geoip database. To use geoip you " \
    "need the geoip city database stored in " GEOIP_PATH ". On Arch Linux this " \
    "can be installed from the geoip-database-extra package."

static GeoIP *gip;

void geoip_init(void)
{
    /* libGeoIP writes to stderr by default instead of letting users handle this
        as appropriate. Need to add GEOIP_SILENCE to shut them up. */
    if (!(gip = GeoIP_open(GEOIP_PATH, GEOIP_STANDARD | GEOIP_SILENCE))) {
        if (errno == ENOENT) {
            errno = 0;
            err_msg(GEOIP_WARNING);
        }
        DEBUG("Error opening %s - disabling geoip", GEOIP_PATH);
    }
}

void geoip_free(void)
{
    if (gip)
        GeoIP_delete(gip);
}

char *geoip_get_location(char *addr, char *buf, int len)
{
    GeoIPRecord *record;

    if (!gip)
        return NULL;

    record = GeoIP_record_by_addr(gip, addr);
    if (!record) {
        strlcpy(buf, "Unknown", len);
        return buf;
    }
    if (record->city && record->country_name) {
        snprintf(buf, len, "%s, %s", record->city, record->country_name);
    } else if (record->country_name) {
        snprintf(buf, len, "%s", record->country_name);
    } else {
        strlcpy(buf, "Unknown", len);
    }
    GeoIPRecord_delete(record);
    return buf;
}

char *geoip_get_country(char *addr)
{
    char *name;
    GeoIPRecord *record;

    if (!gip)
        return NULL;

    name = NULL;
    record = GeoIP_record_by_addr(gip, addr);
    if (record) {
        if (record->country_name)
            name = xstrdup(record->country_name);
        GeoIPRecord_delete(record);
    }
    return name;
}

char *geoip_get_city(char *addr)
{
    char *city;
    GeoIPRecord *record;

    if (!gip)
        return NULL;

    city = NULL;
    record = GeoIP_record_by_addr(gip, addr);
    if (record) {
        if (record->city)
            city = xstrdup(record->city);
        GeoIPRecord_delete(record);
    }
    return city;
}

void geoip_print_version(void)
{
    printf("libGeoIP %s\n", GeoIP_lib_version());
}
