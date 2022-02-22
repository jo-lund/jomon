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

struct icmp6_info {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        uint32_t mtu;
        uint32_t pointer;
        struct {
            uint16_t id;
            uint16_t seq;
            unsigned char *data;
            unsigned int len;
        } echo;
        struct {
            uint8_t cur_hop_limit;
            unsigned int m : 1; /* managed address configuration */
            unsigned int o : 1; /* other configuration */
            uint16_t router_lifetime;
            uint32_t reachable_time;
            uint32_t retrans_timer;
        } router_adv;
        uint8_t target_addr[16];
        struct {
            unsigned int r : 1; /* router flag */
            unsigned int s : 1; /* solicited flag */
            unsigned int o : 1; /* override flag */
            uint8_t target_addr[16];
        } neigh_adv;
        struct {
            uint8_t target_addr[16];
            uint8_t dest_addr[16];
        } redirect;
    };
    struct icmp6_option *option;
};

void register_icmp6(void);
char *get_icmp6_type(uint8_t type);
char *get_icmp6_dest_unreach(uint8_t code);
char *get_icmp6_time_exceeded(uint8_t code);
char *get_icmp6_parameter_problem(uint8_t code);
struct packet_flags *get_icmp6_prefix_flags(void);
int get_icmp6_prefix_flags_size(void);
struct packet_flags *get_icmp6_router_adv_flags(void);
int get_icmp6_router_adv_flags_size(void);
struct packet_flags *get_icmp6_neigh_adv_flags(void);
int get_icmp6_neigh_adv_flags_size(void);

#endif
