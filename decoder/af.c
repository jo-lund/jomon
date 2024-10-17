#include "af.h"

char *get_address_family(uint32_t family)
{
    switch (family) {
    case AFN_IP:
        return "IP Version 4";
    case AFN_IP6:
        return "IP Version 6";
    case AFN_NSAP:
        return "NSAP";
    case AFN_HDLC:
        return "HDLC (8-bit multidrop)";
    case AFN_BBN_1822:
        return "BBN 1822";
    case AFN_802:
        return "Ethernet 802";
    case AFN_E163:
        return "E.163";
    case AFN_E164:
        return "E.164 (SMDS, Frame Relay, ATM)";
    case AFN_F69:
        return "F.69 (Telex)";
    case AFN_X121:
        return "X.121 (X.25, Frame Relay)";
    case AFN_IP_X:
        return "IPX";
    case AFN_ATALK:
        return "Appletalk";
    case AFN_DECNET:
        return "Decnet IV";
    case AFN_BANYAN_VINES:
        return "Banyan Vines";
    default:
        return "Unknown";
    }
}

char *get_bsd_address_family(uint32_t family)
{
    switch (family) {
    case AFN_BSD_INET:
        return "IP Version 4";
    case AFN_FREEBSD_INET6:
    case AFN_DARWIN_INET6:
        return "IP Version 6";
    default:
        return "Unknown";
    }
}
