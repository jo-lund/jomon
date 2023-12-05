#include "../system_information.h"
#include "../jomon.h"

bool get_netstat(char *dev UNUSED, struct linkdef *rx UNUSED, struct linkdef *tx UNUSED)
{
    return false;
}

bool get_memstat(struct memstat *mem UNUSED)
{
    return false;
}

bool get_hwstat(struct hwstat *hw UNUSED)
{
    return false;
}

bool get_cpustat(struct cputime *cpu UNUSED)
{
    return false;
}

bool get_iwstat(char *dev UNUSED, struct wireless *stat UNUSED)
{
    return false;
}
