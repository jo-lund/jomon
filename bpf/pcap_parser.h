#ifndef PCAP_PARSER_H
#define PCAP_PARSER_H

#include <stdbool.h>

#define DEFINE_ALLOC(type, name)                        \
    static inline type *alloc_##name(void)              \
    {                                                   \
        type *t = mempool_alloc(sizeof(*t));            \
        memset(t, 0, sizeof(*t));                       \
        return t;                                       \
    }

struct node {
    int op;
    int k;
    uint8_t size;
    struct proto_offset *poff; /* only used for protocols above ether */
    struct node *left;
    struct node *right;
};

struct proto_offset {
    int offset;
    bool inverse;
    struct proto_offset *next;
};

struct block {
    struct block *p;
    bool inverse;    /* true if 'not' block */
    bool op_inverse; /* true if operator is '!=', '<' or '<=' */
    int relop;
    int insn;
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
