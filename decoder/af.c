#include "af.h"

char *get_address_family(uint32_t family)
{
    switch (family) {
    case AF_IP:
        return "IP Version 4";
    case AF_IP6:
        return "IP Version 6";
    case AF_NSAP:
        return "NSAP";
    case AF_HDLC:
        return "HDLC (8-bit multidrop)";
    case AF_BBN_1822:
        return "BBN 1822";
    case AF_802:
        return "Ethernet 802";
    case AF_E163:
        return "E.163";
    case AF_E164:
        return "E.164 (SMDS, Frame Relay, ATM)";
    case AF_F69:
        return "F.69 (Telex)";
    case AF_X121:
        return "X.121 (X.25, Frame Relay)";
    case AF_IP_X:
        return "IPX";
    case AF_ATALK:
        return "Appletalk";
    case AF_DECNET:
        return "Decnet IV";
    case AF_BANYAN_VINES:
        return "Banyan Vines";
    default:
        return "Unknown";
    }
}

char *get_bsd_address_family(uint32_t family)
{
    switch (family) {
    case AF_BSD_INET:
        return "IP Version 4";
    case AF_FREEBSD_INET6:
    case AF_DARWIN_INET6:
        return "IP Version 6";
    default:
        return "Unknown";
    }
}
