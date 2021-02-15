#include <string.h>
#include "packet_dhcp.h"
#include "../util.h"

#define MIN_DHCP_MSG 264
#define MAX_DHCP_MSG 576
#define DHCP_FIXED_SIZE 236

extern void print_dhcp(char *buf, int n, void *data);
extern void add_dhcp_information(void *widget, void *subwidget, void *data);
static packet_error handle_dhcp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                                struct packet_data *pdata);
static packet_error parse_dhcp_options(unsigned char *buffer, int n,
                                       struct dhcp_info *dhcp);
static uint8_t *parse_bytes(unsigned char **data, uint8_t length);

static struct packet_flags dhcp_flags[] = {
    { "Broadcast", 1, NULL },
    { "Reserved", 15, NULL },
};

static struct protocol_info dhcp_prot = {
    .short_name = "DHCP",
    .long_name = "Dynamic Host Configuration Protocol",
    .decode = handle_dhcp,
    .print_pdu = print_dhcp,
    .add_pdu = add_dhcp_information
};

void register_dhcp()
{
    register_protocol(&dhcp_prot, PORT, DHCP_CLI);
    register_protocol(&dhcp_prot, PORT, DHCP_SRV);
}

/*
 * Format of a BOOTP/DHCP message (RFC 2131):
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 * +---------------+---------------+---------------+---------------+
 * |                            xid (4)                            |
 * +-------------------------------+-------------------------------+
 * |           secs (2)            |           flags (2)           |
 * +-------------------------------+-------------------------------+
 * |                          ciaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          yiaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          siaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          giaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                          chaddr  (16)                         |
 * |                                                               |
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                          sname   (64)                         |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                          file    (128)                        |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                          options (variable)                   |
 * +---------------------------------------------------------------+
 *
 *  FIELD      OCTETS       DESCRIPTION
 *  -----      ------       -----------
 *
 *  op            1  Message op code / message type.
 *                   1 = BOOTREQUEST, 2 = BOOTREPLY
 *  htype         1  Hardware address type, see ARP section in "Assigned
 *                   Numbers" RFC; e.g., '1' = 10mb ethernet.
 *  hlen          1  Hardware address length (e.g.  '6' for 10mb
 *                   ethernet).
 *  hops          1  Client sets to zero, optionally used by relay agents
 *                   when booting via a relay agent.
 *  xid           4  Transaction ID, a random number chosen by the
 *                   client, used by the client and server to associate
 *                   messages and responses between a client and a
 *                   server.
 *  secs          2  Filled in by client, seconds elapsed since client
 *                   began address acquisition or renewal process.
 *  flags         2  Flags (see figure 2).
 *  ciaddr        4  Client IP address; only filled in if client is in
 *                   BOUND, RENEW or REBINDING state and can respond
 *                   to ARP requests.
 *  yiaddr        4  'your' (client) IP address.
 *  siaddr        4  IP address of next server to use in bootstrap;
 *                   returned in DHCPOFFER, DHCPACK by server.
 *  giaddr        4  Relay agent IP address, used in booting via a
 *                   relay agent.
 *  chaddr       16  Client hardware address.
 *  sname        64  Optional server host name, null terminated string.
 *  file        128  Boot file name, null terminated string; "generic"
 *                   name or null in DHCPDISCOVER, fully qualified
 *                   directory-path name in DHCPOFFER.
 *  options     var  Optional parameters field.  See the options
 *                   documents for a list of defined options.
*/
packet_error handle_dhcp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    if (n < MIN_DHCP_MSG)
        return DECODE_ERR;

    unsigned char *ptr = buffer;
    int len = n;
    struct dhcp_info *dhcp;
    packet_error err;

    dhcp = mempool_pealloc(sizeof(struct dhcp_info));
    pdata->data = dhcp;
    pdata->len = n;
    dhcp->op = ptr[0];
    dhcp->htype = ptr[1];
    dhcp->hlen = ptr[2];
    dhcp->hops = ptr[3];
    ptr += 4;
    dhcp->xid = read_uint32be(&ptr);
    dhcp->secs = read_uint16be(&ptr);
    dhcp->flags = read_uint16be(&ptr);
    dhcp->ciaddr = read_uint32le(&ptr);
    dhcp->yiaddr = read_uint32le(&ptr);
    dhcp->siaddr = read_uint32le(&ptr);
    dhcp->giaddr = read_uint32le(&ptr);
    memcpy(dhcp->chaddr, ptr, 16);
    ptr += 16;
    memcpy(dhcp->sname, ptr, 64);
    ptr += 64;
    memcpy(dhcp->file, ptr, 128);
    ptr += 128;
    len -= DHCP_FIXED_SIZE;
    if ((err = parse_dhcp_options(ptr, len, dhcp)) == NO_ERR) {
        pinfo->num_packets++;
        pinfo->num_bytes += n;
    }
    return err;
}

static packet_error parse_dhcp_options(unsigned char *buffer, int n, struct dhcp_info *dhcp)
{
    /* the first 4 bytes of the options field is the magic cookie */
    dhcp->magic_cookie = read_uint32be(&buffer);
    n -= 4;
    dhcp->options = list_init(&d_alloc);
    while (n > 0) {
        struct dhcp_options *opt = MEMPOOL_CALLOC(struct dhcp_options, pe);

        opt->tag = *buffer++;
        n--;
        switch (opt->tag) {
        case DHCP_PAD_OPTION:
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_TIME_OFFSET:
            opt->length = *buffer++;
            if (opt->length != 4)
                return DECODE_ERR;
            opt->i32val = (int32_t) read_uint32be(&buffer);
            n -= 5;
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_ROUTER:
        case DHCP_TIME_SERVER:
        case DHCP_NAME_SERVER:
        case DHCP_DOMAIN_NAME_SERVER:
        case DHCP_LOG_SERVER:
        case DHCP_COOKIE_SERVER:
        case DHCP_LPR_SERVER:
        case DHCP_RESOURCE_LOC_SERVER:
        case DHCP_PATH_MTU_AGING_TIMEOUT:
        case DHCP_NETWORK_INFORMATION_SERVERS:
        case DHCP_NTP_SERVERS:
        case DHCP_VENDOR_SPECIFIC:
        case DHCP_NETBIOS_DD:
        case DHCP_XWINDOWS_SFS:
        case DHCP_NISP_SERVERS:
        case DHCP_IMPRESS_SERVER:
        case DHCP_NETBIOS_NS:
        case DHCP_MOBILE_IP_HA:
            opt->length = *buffer++;
            n--;
            if (opt->length % 4 != 0)
                return DECODE_ERR;
            opt->bytes = parse_bytes(&buffer, opt->length);
            n -= opt->length;
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_PATH_MTU_PLATEAU_TABLE:
            opt->length = *buffer++;
            n--;
            if (opt->length % 2 != 0)
                return DECODE_ERR;
            opt->bytes = parse_bytes(&buffer, opt->length);
            n -= opt->length;
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_IP_FORWARDING:
        case DHCP_NON_LOCAL_SRC_ROUTING:
        case DHCP_IP_TTL:
        case DHCP_MESSAGE_TYPE:
        case DHCP_ALL_SUBNETS_LOCAL:
        case DHCP_PERFORM_MASK_DISCOVERY:
        case DHCP_MASK_SUPPLIER:
        case DHCP_PERFORM_ROUTER_DISCOVERY:
        case DHCP_TRAILER_ENCAPSULATION:
        case DHCP_ETHERNET_ENCAPSULATION:
        case DHCP_TCP_DEFAULT_TTL:
        case DHCP_TCP_KEEPALIVE_GARBARGE:
        case DHCP_NETBIOS_NT:
        case DHCP_OPTION_OVERLOAD:
            opt->length = *buffer++;
            if (opt->length != 1)
                return DECODE_ERR;
            opt->byte = *buffer++;
            n -= 2;
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_POLICY_FILTER:
        case DHCP_STATIC_ROUTE:
            opt->length = *buffer++;
            n--;
            if (opt->length < 8 && opt->length % 8 != 0)
                return DECODE_ERR;
            opt->bytes = parse_bytes(&buffer, opt->length);
            n -= opt->length;
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_HOST_NAME:
        case DHCP_DOMAIN_NAME:
        case DHCP_MERIT_DUMP_FILE:
        case DHCP_ROOT_PATH:
        case DHCP_EXTENSIONS_PATH:
        case DHCP_PARAMETER_REQUEST_LIST:
        case DHCP_NIS_DOMAIN:
        case DHCP_NETBIOS_SCOPE:
        case DHCP_NISP_DOMAIN:
        case DHCP_VENDOR_CLASS_ID:
        case DHCP_TFTP_SERVER_NAME:
            opt->length = *buffer++;
            if (opt->length < 1)  /* minimum length is 1 */
                return DECODE_ERR;
            opt->bytes = parse_bytes(&buffer, opt->length);
            n = n - opt->length - 1;
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_FILE_BOOT_SIZE:
        case DHCP_MAX_DATAGRAM_REASSEMBLY_SIZE:
        case DHCP_MAXIMUM_MESSAGE_SIZE:
        case DHCP_INTERFACE_MTU:
            opt->length = *buffer++;
            if (opt->length != 2)
                return DECODE_ERR;
            opt->u16val = read_uint16be(&buffer);
            n -= 3;
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_SUBNET_MASK:
        case DHCP_SWAP_SERVER:
        case DHCP_REQUESTED_IP_ADDRESS:
        case DHCP_IP_ADDRESS_LEASE_TIME:
        case DHCP_SERVER_IDENTIFIER:
        case DHCP_RENEWAL_TIME_VAL:
        case DHCP_REBINDING_TIME_VAL:
        case DHCP_BROADCAST_ADDRESS:
        case DHCP_ROUTER_SOLICITATION_ADDRESS:
        case DHCP_ARP_CACHE_TIMEOUT:
        case DHCP_TCP_KEEPALIVE_INTERVAL:
            opt->length = *buffer++;
            if (opt->length != 4)
                return DECODE_ERR;
            opt->u32val = read_uint32be(&buffer);
            n -= 5;
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_CLIENT_IDENTIFIER:
            opt->length = *buffer++;
            if (opt->length < 2)  /* minimum length is 2 */
                return DECODE_ERR;
            opt->bytes = parse_bytes(&buffer, opt->length);
            n = n - opt->length - 1;
            list_push_back(dhcp->options, opt);
            break;
        case DHCP_END_OPTION:
            opt->length = 1;
            list_push_back(dhcp->options, opt);
            return NO_ERR;
        default:
            opt->length = *buffer++;
            n--;
            printf("DHCP option not supported: %d\n", opt->tag);
        }
    }
    return DECODE_ERR;
}

static uint8_t *parse_bytes(unsigned char **data, uint8_t length)
{
    unsigned char *ptr = *data;
    uint8_t *bytes;

    bytes = mempool_pealloc(length);
    memcpy(bytes, ptr, length);
    ptr += length;
    *data = ptr;
    return bytes;
}

char *get_dhcp_opcode(uint8_t opcode)
{
    switch (opcode) {
    case DHCP_BOOTREQUEST:
        return "Boot request";
    case DHCP_BOOTREPLY:
        return "Boot reply";
    default:
        return NULL;
    }
}

struct packet_flags *get_dhcp_flags()
{
    return dhcp_flags;
}

int get_dhcp_flags_size()
{
    return ARRAY_SIZE(dhcp_flags);
}

char *get_dhcp_message_type(uint8_t type)
{
    switch (type) {
    case DHCPDISCOVER:
        return "DHCP Discover";
    case DHCPOFFER:
        return "DHCP Offer";
    case DHCPREQUEST:
        return "DHCP Request";
    case DHCPDECLINE:
        return "DHCP Decline";
    case DHCPACK:
        return "DHCP Ack";
    case DHCPNAK:
        return "DHCP Nak";
    case DHCPRELEASE:
        return "DHCP Release";
    case DHCPINFORM:
        return "DHCP Inform";
    default:
        return NULL;
    }
}

char *get_dhcp_option_type(uint8_t type)
{
    switch (type) {
    case DHCP_PAD_OPTION:
        return "Pad";
    case DHCP_TIME_OFFSET:
        return "Time Offset";
    case DHCP_ROUTER:
        return "Router";
    case DHCP_TIME_SERVER:
        return "Time Server";
    case DHCP_NAME_SERVER:
        return "Name Server";
    case DHCP_DOMAIN_NAME_SERVER:
        return "Domain Name Server";
    case DHCP_LOG_SERVER:
        return "Log Server";
    case DHCP_COOKIE_SERVER:
        return "Cokkie Server";
    case DHCP_LPR_SERVER:
        return "LPR Server";
    case DHCP_RESOURCE_LOC_SERVER:
        return "Resource Location Server";
    case DHCP_PATH_MTU_AGING_TIMEOUT:
        return "Path MTU Aging Timeout";
    case DHCP_PATH_MTU_PLATEAU_TABLE:
        return "Path MTU Plateau Table";
    case DHCP_IP_FORWARDING:
        return "IP forwarding";
    case DHCP_NON_LOCAL_SRC_ROUTING:
        return "Non-Local Source Routing Enable/Disable";
    case DHCP_IP_TTL:
        return "Default IP Time-to-live";
    case DHCP_MESSAGE_TYPE:
        return "Message Type";
    case DHCP_ALL_SUBNETS_LOCAL:
        return "All Subnets are Local";
    case DHCP_PERFORM_MASK_DISCOVERY:
        return "Perform Mask Discovery";
    case DHCP_MASK_SUPPLIER:
        return "ask Supplier";
    case DHCP_PERFORM_ROUTER_DISCOVERY:
        return "Perform Router Discovery";
    case DHCP_POLICY_FILTER:
        return "Policy Filter";
    case DHCP_HOST_NAME:
        return "Host Name";
    case DHCP_DOMAIN_NAME:
        return "Domain Name";
    case DHCP_MERIT_DUMP_FILE:
        return "Merit Dump File";
    case DHCP_ROOT_PATH:
        return "Root Path";
    case DHCP_EXTENSIONS_PATH:
        return "Extensions Path";
    case DHCP_PARAMETER_REQUEST_LIST:
        return "Parameter Request List";
    case DHCP_FILE_BOOT_SIZE:
        return "File Boot Size";
    case DHCP_MAX_DATAGRAM_REASSEMBLY_SIZE:
        return "Maximum Datagram Reassembly Size";
    case DHCP_MAXIMUM_MESSAGE_SIZE:
        return "Maximum Message Size";
    case DHCP_INTERFACE_MTU:
        return "Interface MTU";
    case DHCP_SUBNET_MASK:
        return "Subnet Mask";
    case DHCP_SWAP_SERVER:
        return "Swap Server";
    case DHCP_REQUESTED_IP_ADDRESS:
        return "Requested IP Address";
    case DHCP_IP_ADDRESS_LEASE_TIME:
        return "IP Address Lease Time";
    case DHCP_SERVER_IDENTIFIER:
        return "Server Identifier";
    case DHCP_RENEWAL_TIME_VAL:
        return "Renewal (T1) Time Value";
    case DHCP_REBINDING_TIME_VAL:
        return "Rebinding (T2) Time Value";
    case DHCP_BROADCAST_ADDRESS:
        return "Broadcast Address";
    case DHCP_CLIENT_IDENTIFIER:
        return "Client Identifier";
    case DHCP_NETBIOS_NS:
        return "NetBIOS over TCP/IP Name Server";
    case DHCP_NETBIOS_DD:
        return "NetBIOS over TCP/IP Datagram Distribution Server";
    case DHCP_LDAP_SERVERS:
        return "LDAP Servers";
    case DHCP_DOMAIN_SEARCH:
        return "Domain Search";
    case DHCP_ROUTER_SOLICITATION_ADDRESS:
        return "Router Solicitation Address";
    case DHCP_STATIC_ROUTE:
        return "Static Route";
    case DHCP_TRAILER_ENCAPSULATION:
        return "Trailer Encapsulation";
    case DHCP_ARP_CACHE_TIMEOUT:
        return "ARP Cache Timeout";
    case DHCP_ETHERNET_ENCAPSULATION:
        return "Ethernet Encapsulation";
    case DHCP_TCP_DEFAULT_TTL:
        return "TCP Default TTL";
    case DHCP_TCP_KEEPALIVE_INTERVAL:
        return "TCP Keepalive Interval";
    case DHCP_TCP_KEEPALIVE_GARBARGE:
        return "TCP Keepalive Garbage";
    case DHCP_NIS_DOMAIN:
        return "Network Information Service Domain";
    case DHCP_NETWORK_INFORMATION_SERVERS:
        return "Network Information Servers";
    case DHCP_NTP_SERVERS:
        return "Network Time Protocol Servers";
    case DHCP_VENDOR_SPECIFIC:
        return "Vendor Specific Information";
    case DHCP_NETBIOS_NT:
        return "NetBIOS over TCP/IP Node Type";
    case DHCP_NETBIOS_SCOPE:
        return "NetBIOS over TCP/IP Scope";
    case DHCP_XWINDOWS_SFS:
        return "X Window System Font Server";
    case DHCP_XWINDOWS_DM:
        return "X Window System Display Manager";
    case DHCP_NISP_DOMAIN:
        return "Network Information Service+ Domain";
    case DHCP_NISP_SERVERS:
        return "Network Information Service+ Servers";
    case DHCP_VENDOR_CLASS_ID:
        return "Vendor Class Identifier";
    case DHCP_IMPRESS_SERVER:
        return "Impress Server";
    case DHCP_TFTP_SERVER_NAME:
        return "TFTP Server Name";
    case DHCP_OPTION_OVERLOAD:
        return "Option Overload";
    case DHCP_MOBILE_IP_HA:
        return "Mobile IP Home Agent";
    case 252:
        return "Private Use";
    case DHCP_END_OPTION:
        return "End";
    default:
        return NULL;
    }
}

char *get_dhcp_netbios_node_type(uint8_t type)
{
    switch (type) {
    case 0x1:
        return "B-node";
    case 0x2:
        return "P-node";
    case 0x4:
        return "M-node";
    case 0x8:
        return "H-node";
    default:
        return NULL;
    }
}

char *get_dhcp_option_overload(uint8_t type)
{
    switch (type) {
    case 1:
        return "The \'file\' field is used to hold options";
    case 2:
        return "The \'sname\' field is used to hold options";
    case 3:
        return "Both the \'file\' and \'sname\' fields are used to hold options";
    default:
        return NULL;
    }
}
