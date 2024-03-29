#ifndef PACKET_DHCP_H
#define PACKET_DHCP_H

#include "packet.h"

#define DHCP_COOKIE 0x63825363

/* message opcode */
#define DHCP_BOOTREQUEST 1
#define DHCP_BOOTREPLY 2

/* DHCP options */
#define DHCP_PAD_OPTION 0
#define DHCP_END_OPTION 255
#define DHCP_SUBNET_MASK 1
#define DHCP_TIME_OFFSET 2
#define DHCP_ROUTER 3
#define DHCP_TIME_SERVER 4
#define DHCP_NAME_SERVER 5
#define DHCP_DOMAIN_NAME_SERVER 6
#define DHCP_LOG_SERVER 7
#define DHCP_COOKIE_SERVER 8
#define DHCP_LPR_SERVER 9
#define DHCP_IMPRESS_SERVER 10
#define DHCP_RESOURCE_LOC_SERVER 11
#define DHCP_HOST_NAME 12
#define DHCP_FILE_BOOT_SIZE 13
#define DHCP_MERIT_DUMP_FILE 14
#define DHCP_DOMAIN_NAME 15
#define DHCP_SWAP_SERVER 16
#define DHCP_ROOT_PATH 17
#define DHCP_EXTENSIONS_PATH 18
#define DHCP_IP_FORWARDING 19
#define DHCP_NON_LOCAL_SRC_ROUTING 20
#define DHCP_POLICY_FILTER 21
#define DHCP_MAX_DATAGRAM_REASSEMBLY_SIZE 22
#define DHCP_IP_TTL 23
#define DHCP_PATH_MTU_AGING_TIMEOUT 24 /* The value is in units of seconds */
#define DHCP_PATH_MTU_PLATEAU_TABLE 25
#define DHCP_INTERFACE_MTU 26
#define DHCP_ALL_SUBNETS_LOCAL 27
#define DHCP_BROADCAST_ADDRESS 28
#define DHCP_PERFORM_MASK_DISCOVERY 29
#define DHCP_MASK_SUPPLIER 30
#define DHCP_PERFORM_ROUTER_DISCOVERY 31
#define DHCP_ROUTER_SOLICITATION_ADDRESS 32
#define DHCP_STATIC_ROUTE 33
#define DHCP_TRAILER_ENCAPSULATION 34
#define DHCP_ARP_CACHE_TIMEOUT 35
#define DHCP_ETHERNET_ENCAPSULATION 36
#define DHCP_TCP_DEFAULT_TTL 37
#define DHCP_TCP_KEEPALIVE_INTERVAL 38
#define DHCP_TCP_KEEPALIVE_GARBARGE 39
#define DHCP_NIS_DOMAIN 40
#define DHCP_NETWORK_INFORMATION_SERVERS 41
#define DHCP_NTP_SERVERS 42
#define DHCP_VENDOR_SPECIFIC 43
#define DHCP_NETBIOS_NS 44
#define DHCP_NETBIOS_DD 45
#define DHCP_NETBIOS_NT 46
#define DHCP_NETBIOS_SCOPE 47
#define DHCP_XWINDOWS_SFS 48
#define DHCP_XWINDOWS_DM 49
#define DHCP_REQUESTED_IP_ADDRESS 50
#define DHCP_IP_ADDRESS_LEASE_TIME 51 /* The value is in units of seconds */
#define DHCP_OPTION_OVERLOAD 52
#define DHCP_MESSAGE_TYPE 53
#define DHCP_SERVER_IDENTIFIER 54
#define DHCP_PARAMETER_REQUEST_LIST 55
#define DHCP_MESSAGE 56
#define DHCP_MAXIMUM_MESSAGE_SIZE 57
#define DHCP_RENEWAL_TIME_VAL 58    /* The value is in units of seconds */
#define DHCP_REBINDING_TIME_VAL 59  /* The value is in units of seconds */
#define DHCP_VENDOR_CLASS_ID 60
#define DHCP_CLIENT_IDENTIFIER 61
#define DHCP_NISP_DOMAIN 64
#define DHCP_NISP_SERVERS 65
#define DHCP_TFTP_SERVER_NAME 66
#define DHCP_BOOTFILE_NAME 67
#define DHCP_MOBILE_IP_HA 68
#define DHCP_SMTP_SERVER 69
#define DHCP_POP3_SERVER 70
#define DHCP_NNTP_SERVER 71
#define DHCP_WWW_SERVER 72
#define DHCP_FINGER_SERVER 73
#define DHCP_IRC_SERVER 74
#define DHCP_STREETTALK_SERVER 75
#define DHCP_STDA_SERVER 76
#define DHCP_CLIENT_FQDN 81
#define DHCP_CLIENT_SA 93
#define DHCP_CLIENT_NDI 94
#define DHCP_LDAP_SERVERS 95 /* RFC 3679 */
#define DHCP_UUID_CLIENT_ID 97
#define DHCP_DOMAIN_SEARCH 119 /* RFC 3397 */
#define DHCP_CLASSLESS_STATIC_ROUTE 121 /* RFC 3442 */
#define DHCP_MS_CLASSLESS_STATIC_ROUTE 249

/* DHCP client architecture type */
#define IA_X86_PC 0
#define NEC_PC98 1
#define IA64_PC 2
#define DEC_ALPHA 3
#define ARCX86 4
#define ILC 5

/* DHCP message type */
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

struct dhcp_options {
    uint8_t tag;
    uint8_t length;
    union {
        uint32_t u32val;
        int32_t i32val;
        uint16_t u16val;
        uint8_t *bytes;
        uint8_t byte;
        struct {
            uint8_t flags;
            uint8_t rcode1; /* deprecated */
            uint8_t rcode2; /* deprecated */
            uint8_t *name;
        } fqdn;
        struct {
            uint8_t type; /* should be 1 */
            uint8_t maj;
            uint8_t min;
        } ndi;
    };
};

struct dhcp_info {
    uint8_t op;     /* opcode */
    uint8_t htype;  /* hardware address type */
    uint8_t hlen;   /* hardware address length */
    uint8_t hops;
    uint32_t xid;   /* transaction id */
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr; /* Client ip address. Filled in by client in boot request if known) */
    uint32_t yiaddr; /* Your (client) ip address. Filled in by server if client doesn't
                        know its own address (ciaddr was 0).*/
    uint32_t siaddr; /* Server ip address. Returned in bootreply by server. */
    uint32_t giaddr; /* Gateway ip address, used in optional cross-gateway booting */
    uint8_t chaddr[16]; /* client hardware address. Filled in by client  */
    char sname[64]; /* optional server host-name (null terminated)*/
    char file[128]; /* boot file name (null terminated) */
    uint32_t magic_cookie;
    list_t *options;
};

void register_dhcp(void);
char *get_dhcp_opcode(uint8_t opcode);
struct packet_flags *get_dhcp_flags(void);
int get_dhcp_flags_size(void);
struct packet_flags *get_dhcp_fqdn_flags(void);
int get_dhcp_fqdn_flags_size(void);
char *get_dhcp_option_type(uint8_t type);
char *get_dhcp_message_type(uint8_t type);
char *get_dhcp_netbios_node_type(uint8_t type);
char *get_dhcp_option_overload(uint8_t type);
char *get_dhcp_option_architecture(uint8_t type);

#endif
