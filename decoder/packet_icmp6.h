#ifndef PACKET_IMAP6_H
#define PACKET_IMAP6_H

#define ICMP6_DST_UNREACH_FAILED_POLICY 5
#define ICMP6_DST_UNREACH_REJECT_ROUTE 6

struct icmp6_option {
    uint8_t type;
    uint8_t length;
    union {
        uint8_t *source_addr;
        uint8_t *target_addr;
        uint32_t mtu;
        struct {
            uint8_t prefix_length;
            unsigned int l : 1; /* on-link flag */
            unsigned int a : 1; /* autonomous address-configuration */
            uint32_t valid_lifetime;
            uint32_t pref_lifetime;
            uint8_t *prefix;
        } prefix_info;
    };
    struct icmp6_option *next;
};

void register_icmp6(void);

#endif
