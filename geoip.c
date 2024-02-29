#include <GeoIP.h>
#include <GeoIPCity.h>
#include <stdbool.h>
#include "geoip.h"
#include "config.h"
#include "wrapper.h"

static GeoIP *gip;

bool geoip_init(void)
{
    if (!(gip = GeoIP_open(GEOIP_PATH, GEOIP_STANDARD)))
        return false;
    return true;
}

void geoip_free(void)
{
    if (gip)
        GeoIP_delete(gip);
}

char *geoip_get_location(char *addr, char *buf, int len)
{
    if (!gip)
        return NULL;

    GeoIPRecord *record = GeoIP_record_by_addr(gip, addr);

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
    if (!gip)
        return NULL;

    char *name = NULL;
    GeoIPRecord *record = GeoIP_record_by_addr(gip, addr);

    if (record) {
        if (record->country_name)
            name = xstrdup(record->country_name);
        GeoIPRecord_delete(record);
    }
    return name;
}

char *geoip_get_city(char *addr)
{
    if (!gip)
        return NULL;

    char *city = NULL;
    GeoIPRecord *record = GeoIP_record_by_addr(gip, addr);

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
