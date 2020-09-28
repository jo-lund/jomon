#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <setjmp.h>
#include <string.h>
#include "parse.h"
#include "bpf.h"
#include "pcap_lexer.h"
#include "pcap_parser.h"
#include "genasm.h"
#include "optimize.h"
#include "../mempool.h"
#include "../debug_file.h"
#include "../vector.h"

static int lbp[128] = {
    [PCAP_MUL] = 60,
    [PCAP_DIV] = 60,
    [PCAP_MOD] = 60,
    [PCAP_ADD] = 50,
    [PCAP_SUB] = 50,
    [PCAP_SHL] = 40,
    [PCAP_SHR] = 40,
    [PCAP_AND] = 30,
    [PCAP_XOR] = 20,
    [PCAP_OR] = 10
};

static struct bpf_parser parser;
static jmp_buf env;
static struct node *parse_expr(int rbp);

#define make_leaf_node(n, o, v)                 \
    do {                                        \
        n = alloc_node();                       \
        n->op = o;                              \
        n->k = v;                               \
    } while (0)

#define make_node(n, o, l, r)                   \
    do {                                        \
        n = alloc_node();                       \
        n->op = o;                              \
        n->left = l;                            \
        n->right = r;                           \
    } while (0)

#define make_block(b, o, l, r)                  \
    do {                                        \
        b = alloc_block();                      \
        b->relop = o;                           \
        b->expr1 = l;                           \
        b->expr2 = r;                           \
    } while (0)

#define get_token() pcap_lex(&parser)

DEFINE_ALLOC(struct node, node);
DEFINE_ALLOC(struct block, block);

static inline bool match(int token)
{
    return (parser.token = get_token()) == token;
}

static int get_lbp(int token)
{
    switch (token) {
    case PCAP_EOF:
    case PCAP_RBRACKET:
    case PCAP_LAND:
    case PCAP_LOR:
    case PCAP_EQ:
    case PCAP_LE:
    case PCAP_GT:
    case PCAP_GEQ:
    case PCAP_LEQ:
    case PCAP_NEQ:
    case PCAP_COL:
    case PCAP_MUL:
    case PCAP_DIV:
    case PCAP_MOD:
    case PCAP_ADD:
    case PCAP_SUB:
    case PCAP_SHL:
    case PCAP_SHR:
    case PCAP_AND:
    case PCAP_XOR:
    case PCAP_OR:
        return lbp[token];
    default:
        DEBUG("%s: Unexpected token", __func__);
        longjmp(env, -1);
    }
}

static struct node *parse_offset(int token)
{
    if (match(PCAP_LBRACKET)) {
        struct node *n;
        struct node *c;

        make_leaf_node(n, token, 0);
        parser.token = get_token();
        c = parse_expr(0);
        n->left = c;
        switch (parser.token) {
        case PCAP_COL:
            if (match(PCAP_INT)) {
                c->size = parser.val.intval;
                if (match(PCAP_RBRACKET)) {
                    return n;
                }
            }
            break;
        case PCAP_RBRACKET:
            c->size = 1;
            return n;
        default:
            break;
        }
    }
    DEBUG("%s: Unexpected token", __func__);
    longjmp(env, -1);
}

static struct node *nud(int token)
{
    struct node *n;

    switch (token) {
    case PCAP_INT:
        make_leaf_node(n, token, parser.val.intval);
        return n;
    case PCAP_SUB:
        if (match(PCAP_INT)) {
            make_leaf_node(n, parser.token, -parser.val.intval);
            return n;
        }
        /* TODO: Handle parenthesis */
        DEBUG("%s: Unexpected token", __func__);
        longjmp(env, -1);
    case PCAP_ETHER:
    case PCAP_IP:
    case PCAP_ARP:
    case PCAP_RARP:
    case PCAP_TCP:
    case PCAP_UDP:
    case PCAP_ICMP:
    case PCAP_IP6:
        return parse_offset(token);
    default:
        DEBUG("%s: Unexpected token", __func__);
        longjmp(env, -1);
    }
}

static struct node *led(int token, struct node *left)
{
    struct node *n;

    switch (token) {
    case PCAP_ADD:
        make_node(n, token, left, parse_expr(50));
        return n;
    case PCAP_SUB:
        make_node(n, token, left, parse_expr(50));
        return n;
    case PCAP_MUL:
        make_node(n, token, left, parse_expr(60));
        return n;
    case PCAP_DIV:
        make_node(n, token, left, parse_expr(60));
        return n;
    case PCAP_MOD:
        make_node(n, token, left, parse_expr(60));
        return n;
    case PCAP_AND:
        make_node(n, token, left, parse_expr(30));
        return n;
    case PCAP_OR:
        make_node(n, token, left, parse_expr(20));
        return n;
    case PCAP_XOR:
        make_node(n, token, left, parse_expr(10));
        return n;
    case PCAP_SHL:
        make_node(n, token, left, parse_expr(40));
        return n;
    case PCAP_SHR:
        make_node(n, token, left, parse_expr(40));
        return n;
    default:
        return NULL;
    }
}

static struct node *parse_expr(int rbp)
{
    int token = parser.token;
    struct node *left;

    left = nud(token);
    parser.token = get_token();
    while (rbp < get_lbp(parser.token)) {
        token = parser.token;
        parser.token = get_token();
        left = led(token, left);
    }
    return left;
}

static struct block *parse_relop(struct node *n)
{
    int token = parser.token;
    struct block *b;

    switch (token) {
    case PCAP_EQ:
    case PCAP_LE:
    case PCAP_GT:
    case PCAP_GEQ:
    case PCAP_LEQ:
    case PCAP_NEQ:
        parser.token = get_token();
        make_block(b, token, n, parse_expr(0));
        return b;
    default:
        DEBUG("%s: Unexpected relop: %d", __func__, parser.token);
        longjmp(env, -1);
    }
}

static struct block *parse_op(struct block *b0)
{
    if (b0 == NULL)
        return NULL;

    struct block *b1;
    struct node *n;
    int token = parser.token;

    parser.token = get_token();
    if ((n = parse_expr(0)) == NULL)
        return NULL;
    b1 = parse_relop(n);
    b0->next = b1;
    if (token == PCAP_LAND)
        b0->jt = b1;
    else
        b0->jf = b1;
    return b1;
}

static void patch_blocks_helper(struct block *b, struct block **and, struct block **or)
{
    if (b == NULL)
        return;

    if (b->jt) {
        patch_blocks_helper(b->jt, and, or);
        *and = b->jt;
        b->jf = *or;
    } else if (b->jf) {
        patch_blocks_helper(b->jf, and, or);
        *or = b->jf;
        b->jt = *and;
    }
}

static void patch_blocks(struct block *b)
{
    struct block *b0 = NULL;
    struct block *b1 = NULL;

    patch_blocks_helper(b, &b0, &b1);
}

struct bpf_prog pcap_compile(char *filter)
{
    struct bpf_prog prog = {
        .bytecode = NULL,
        .size = 0
    };
    struct block *head = NULL;

    parser.input.buf = (unsigned char *) filter;
    parser.input.tok = parser.input.buf;
    parser.input.cur = parser.input.buf;
    parser.input.lim = parser.input.buf + strlen((char *) parser.input.buf) + 1;
    parser.line = 1;
    if (setjmp(env) == 0) {
        struct block *b = NULL;
        struct node *n;

        /* TODO: Handle 'not' and parenthesis */
        parser.token = get_token();
        while (parser.token != PCAP_EOF) {
            switch (parser.token) {
            case PCAP_LAND:
            case PCAP_LOR:
                if ((b = parse_op(b)) == NULL)
                    goto done;
                break;
            default:
                if ((n = parse_expr(0)) == NULL)
                    goto done;
                head = parse_relop(n);
                b = head;
                break;
            }
        }
        patch_blocks(head);
        prog = gencode(head);
    }

done:
    mempool_shfree(NULL);
    return prog;

}
