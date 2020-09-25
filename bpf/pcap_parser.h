#ifndef PCAP_PARSER_H
#define PCAP_PARSER_H

#define DEFINE_ALLOC(type, name)                        \
    static inline type *alloc_##name(void)              \
    {                                                   \
        type *t = mempool_shalloc(sizeof(*t));          \
        memset(t, 0, sizeof(*t));                       \
        return t;                                       \
    }

struct node {
    int op;
    int k;
    uint8_t size;
    uint8_t su;
    struct node *left;
    struct node *right;
};

struct proto_offset {
    int offset;
    bool inverse;
    struct proto_offset *next;
};

struct block {
    bool inverse;
    int relop;
    int insn;
    struct proto_offset *poff; /* only used for protocols above ether */
    struct node *expr1;
    struct node *expr2;
    struct block *next;
    struct block *jt;
    struct block *jf;
};

/*
 * Compiles a filter expression in libpcap syntax. Allocates memory for bytecode
 * that needs to be freed after use.
 */
struct bpf_prog pcap_compile(char *filter);

#endif
