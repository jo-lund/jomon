#ifndef PACKET_VRRP
#define PACKET_VRRP

#include <stdint.h>

#define VRRP_PRIORITY_MASTER_RELEASE 0
#define VRRP_PRIORITY_BACKUP_DEFAULT 100
#define VRRP_PRIORITY_OWN_IP 255
#define VRRP_NO_AUTHENTICATION 0
#define VRRP_V1_AUTH_STP 1
#define VRRP_V1_IP_AUTH_HDR 2

struct vrrp_info {
    unsigned int version : 4;
    unsigned int type : 4;
    uint8_t vrid;
    uint8_t priority;
    uint8_t count_ip; /* the number of ip addresses in the VRRP advertisement */
    union {
        struct {
            unsigned int rsvd : 4; /* reserved in version 3 */
            unsigned int max_advr_int : 12; /* time interval in centiseconds between advertisements */
        } v3;
        struct {
            uint8_t auth_type;
            uint8_t advr_int; /* time interval in seconds between advertisements */
            char auth_str[9];
        } v;
    };
    uint16_t checksum;
    union {
        uint32_t *ip4_addrs;
        uint8_t *ip6_addrs;
    };
};

char *get_vrrp_type(uint8_t type);
char *get_vrrp_auth(uint8_t auth);

void register_vrrp(void);

#endif
