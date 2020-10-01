#include <stdlib.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include "genasm.h"
#include "pcap_lexer.h"
#include "pcap_parser.h"
#include "bpf.h"
#include "../vector.h"
#include "../stack.h"
#include "../util.h"
#include "../mempool.h"

#define NUM_REGS 2
#define A 0
#define X 1

#define ETH_FRAME_TYPE_OFFSET 12
#define ETH_OFFSET 0
#define NETWORK_OFFSET ETH_HLEN

static vector_t *code;
static uint32_t regs[NUM_REGS];
static uint32_t M[BPF_MEMWORDS];
static _stack_t *memidx;
static int block_insn = 0;
static void genexpr(struct block *b, struct node *n, int op, int offset);

static const char *instable[] = {
    [BPF_LD | BPF_W] = "ld",
    [BPF_LD | BPF_H] = "ldh",
    [BPF_LD | BPF_B] = "ldb",
    [BPF_LDX | BPF_W] = "ldx",
    [BPF_ST] = "st",
    [BPF_STX] = "stx",
    [BPF_ALU | BPF_ADD] = "add",
    [BPF_ALU | BPF_SUB] = "sub",
    [BPF_ALU | BPF_MUL] = "mul",
    [BPF_ALU | BPF_DIV] = "div",
    [BPF_ALU | BPF_AND] = "and",
    [BPF_ALU | BPF_OR] = "or",
    [BPF_ALU | BPF_XOR] = "xor",
    [BPF_ALU | BPF_LSH] = "lsh",
    [BPF_ALU | BPF_RSH] = "rsh",
    [BPF_ALU | BPF_NEG] = "not",
    [BPF_ALU | BPF_MOD] = "mod",
    [BPF_JMP | BPF_JA] = "jmp",
    [BPF_JMP | BPF_JEQ] = "jeq",
    [BPF_JMP | BPF_JGT] = "jgt",
    [BPF_JMP | BPF_JGE] = "jge",
    [BPF_JMP | BPF_JSET] = "jset",
    [BPF_RET] = "ret",
    [BPF_MISC | BPF_TAX] = "tax",
    [BPF_MISC | BPF_TXA] = "txa"
};

#define is_proto(c)                                                     \
    (c == PCAP_ETHER || c == PCAP_IP || c == PCAP_IP6                   \
     || c == PCAP_ARP || c == PCAP_RARP || c == PCAP_TCP                \
     || c == PCAP_UDP || c == PCAP_ICMP)

#define is_transport(c) (c == PCAP_UDP || c == PCAP_TCP || c == PCAP_ICMP)

#define set_jmp_offset(b, insn, jmp, i)                 \
    do {                                                \
        struct block *b1 = b->next;                     \
        int c = 0;                                      \
        bool iset = false;                              \
        while (b1) {                                    \
            if (b->jmp == b1) {                         \
                insn->jmp = (i > 0) ? c + i - 1 : c;    \
                iset = true;                            \
                break;                                  \
            }                                           \
            c += b1->insn;                              \
            b1 = b1->next;                              \
        }                                               \
        if (!iset)                                      \
            insn->jmp = c + i;                          \
    } while (0)

DEFINE_ALLOC(struct proto_offset, offset);

static int alloc_mem(void)
{
    for (int i = 1; i < BPF_MEMWORDS; i++) {
        if (M[i] == 0) {
            M[i] = 1;
            return i;
        }
    }
    return -1;
}

static int get_ldsize(int size)
{
    switch (size) {
    case 1:
        return BPF_LD | BPF_B;
    case 2:
        return BPF_LD | BPF_H;
    case 4:
        return BPF_LD | BPF_W;
    default:
        return 0;
    }
}

static void gen_tax(void)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    insn->code = BPF_MISC | BPF_TAX;
    vector_push_back(code, insn);
    block_insn++;
    regs[A] = 0;
}

static void gen_st(void)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    insn->code = BPF_ST;
    insn->k = alloc_mem();
    stack_push(memidx, INT_TO_PTR(insn->k));
    vector_push_back(code, insn);
    block_insn++;
}

static void gen_ldind(struct node *n, int k)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    insn->code = BPF_LD | get_ldsize(n->size) | BPF_IND;
    insn->k = k;
    vector_push_back(code, insn);
    block_insn++;
}

static void gen_lda(struct node *n, int mode)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    if (regs[A])
        gen_st();
    else
        regs[A] = 1;
    insn->code = BPF_LD | get_ldsize(n->size) | BPF_K | mode;
    insn->k = n->k;
    vector_push_back(code, insn);
    block_insn++;
}

static void gen_ldm(struct node *n)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    if (regs[A])
        gen_st();
    else
        regs[A] = 1;
    insn->code = BPF_LD | get_ldsize(n->size) | BPF_K | BPF_MEM;
    insn->k = PTR_TO_INT(stack_pop(memidx));
    vector_push_back(code, insn);
    block_insn++;
}

/* Need to check if index register is taken? */
static void gen_lmsh(uint32_t k)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    insn->code = BPF_LDX | BPF_B | BPF_MSH;
    insn->k = k;
    vector_push_back(code, insn);
    block_insn++;
}

static void set_alu_code(struct bpf_insn *insn, int op, int src)
{
    switch (op) {
    case PCAP_MUL:
        insn->code = BPF_ALU | BPF_MUL | src;
        break;
    case PCAP_DIV:
        insn->code = BPF_ALU | BPF_DIV | src;
        break;
    case PCAP_MOD:
        insn->code = BPF_ALU | BPF_MOD | src;
        break;
    case PCAP_ADD:
        insn->code = BPF_ALU | BPF_ADD | src;
        break;
    case PCAP_SUB:
        insn->code = BPF_ALU | BPF_SUB | src;
        break;
    case PCAP_SHL:
        insn->code = BPF_ALU | BPF_LSH | src;
        break;
    case PCAP_SHR:
        insn->code = BPF_ALU | BPF_RSH | src;
        break;
    case PCAP_OR:
        insn->code = BPF_ALU | BPF_OR | src;
        break;
    case PCAP_AND:
        insn->code = BPF_ALU | BPF_AND | src;
        break;
    case PCAP_XOR:
        insn->code = BPF_ALU | BPF_XOR | src;
        break;
    default:
        break;
    }
}

static void gen_alu(struct node *n)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    set_alu_code(insn, n->op, BPF_K);
    if (n->right->op == PCAP_INT) {
        insn->k = n->right->k;
    } else if (n->left->op == PCAP_INT) {
        insn->k = n->left->k;
    }
    vector_push_back(code, insn);
    block_insn++;
}

static void gen_alux(struct node *n)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    set_alu_code(insn, n->op, BPF_X);
    insn->k = 0;
    vector_push_back(code, insn);
    block_insn++;
    regs[X] = 0;
}

static void gen_network(struct block *b, struct node *n, uint16_t ethertype)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    b->poff = alloc_offset();
    b->poff->offset = block_insn + 1;
    n->k = ETH_FRAME_TYPE_OFFSET;
    n->size = 2;
    gen_lda(n, BPF_ABS);
    insn->code = BPF_JMP | BPF_JEQ | BPF_K;
    insn->k = ethertype;
    vector_push_back(code, insn);
    block_insn++;
    regs[A] = 0;
}

static void gen_transport(struct block *b, struct node *n, uint32_t prot)
{
    struct bpf_insn *insn;
    struct proto_offset *npoff;

    /* Block 1: Check if IPV4 */
    gen_network(b, n, ETH_P_IP); /* TODO: If not IPV4, check for IPV6 */

    /* Block 2: Check if TCP/UDP/ICMP */
    b->poff->next = alloc_offset();
    npoff = b->poff->next;
    npoff->offset = block_insn + 1;
    n->k = 23;
    n->size = 1;
    gen_lda(n, BPF_ABS);
    insn = calloc(1, sizeof(*insn));
    insn->code = BPF_JMP | BPF_JEQ | BPF_K;
    insn->k = prot;
    vector_push_back(code, insn);
    block_insn++;
    regs[A] = 0;

    /* Block 3: Only accept unfragmented or frag 0 IPv4 packets */
    npoff->next = alloc_offset();
    npoff = npoff->next;
    npoff->offset = block_insn + 1;
    npoff->inverse = true;
    n->k = 20;
    n->size = 2;
    gen_lda(n, BPF_ABS);
    insn = calloc(1, sizeof(*insn));
    insn->code = BPF_JMP | BPF_JSET | BPF_K;
    insn->k = 0x1fff;
    vector_push_back(code, insn);
    block_insn++;
    regs[A] = 0;
}

static void gen_proto(struct block *b, struct node *n, int op, int offset)
{
    if (n == NULL)
        return;

    genexpr(b, n->left, n->op, offset);
    if (is_proto(op)) {
        gen_tax();
        gen_ldind(n, 0);
    }
}

static void genexpr(struct block *b, struct node *n, int op, int offset)
{
    if (n == NULL)
        return;

    switch (n->op) {
    case PCAP_ETHER:
        gen_proto(b, n, op, offset);
        break;
    case PCAP_IP:
        gen_network(b, n, ETH_P_IP);
        offset = NETWORK_OFFSET;
        gen_proto(b, n, op, offset);
        break;
    case PCAP_IP6:
        gen_network(b, n, ETH_P_IPV6);
        offset = NETWORK_OFFSET;
        gen_proto(b, n, op, offset);
        break;
    case PCAP_ARP:
        gen_network(b, n, ETH_P_ARP);
        offset = NETWORK_OFFSET;
        gen_proto(b, n, op, offset);
        break;
    case PCAP_RARP:
        gen_network(b, n, ETH_P_RARP);
        offset = NETWORK_OFFSET;
        gen_proto(b, n, op, offset);
        break;
    case PCAP_TCP:
        gen_transport(b, n, IPPROTO_TCP);
        offset = NETWORK_OFFSET;
        gen_proto(b, n, op, offset);
        break;
    case PCAP_UDP:
        gen_transport(b, n, IPPROTO_UDP);
        offset = NETWORK_OFFSET;
        gen_proto(b, n, op, offset);
        break;
    case PCAP_ICMP:
        gen_transport(b, n, IPPROTO_ICMP);
        offset = NETWORK_OFFSET;
        gen_proto(b, n, op, offset);
        break;
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
        genexpr(b, n->left, n->op, offset);
        genexpr(b, n->right, n->op, offset);
        if (n->left->op != PCAP_INT && n->right->op != PCAP_INT) {
            gen_tax();
            gen_ldm(n);
            gen_alux(n);
            break;
        }
        if (n->left->op == PCAP_INT && n->right->op == PCAP_INT)
            gen_lda(n->left, BPF_IMM);
        if (n->right->op != PCAP_INT) {
            gen_tax();
            gen_lda(n->left, BPF_IMM);
            gen_alux(n);
        } else {
            gen_alu(n);
        }
        if (is_proto(op)) {
            gen_tax();
            gen_ldind(n, 0);
        }
        break;
    case PCAP_INT:
        if (is_proto(op)) {
            n->k += offset;
            if (is_transport(op)) {
                gen_lmsh(14);
                gen_ldind(n, n->k);
            } else {
                gen_lda(n, BPF_ABS);
            }
        }
        break;
    default:
        break;
    }
}

static void gen_ret(int k)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    insn->code = BPF_RET;
    insn->k = k;
    vector_push_back(code, insn);
}

static void gen_jmpins(struct block *b, int ins)
{
    struct bpf_insn *insn = calloc(1, sizeof(*insn));

    if (b->expr2->op == PCAP_INT) {
        insn->code = BPF_JMP | ins | BPF_K;
        insn->k = b->expr2->k;
    } else {
        gen_tax();
        gen_ldm(b->expr1);
        insn->code = BPF_JMP | ins | BPF_X;
    }
    vector_push_back(code, insn);
    block_insn++;
    regs[A] = 0;
}

static void genjmp(struct block *b)
{
    switch (b->relop) {
    case PCAP_EQ:
        gen_jmpins(b, BPF_JEQ);
        break;
    case PCAP_LE:
        break;
    case PCAP_GT:
        gen_jmpins(b, BPF_JGT);
        break;
    case PCAP_GEQ:
        gen_jmpins(b, BPF_JGE);
        break;
    case PCAP_LEQ:
    case PCAP_NEQ:
        break;
    default:
        break;
    }
}

static void patch_jmp(struct block *b, int numi)
{
    if (b == NULL)
        return;

    struct bpf_insn *insn;
    struct proto_offset *poff = b->poff;
    int offset;

    while (poff) {
        insn = vector_get_data(code, numi + poff->offset);
        offset = poff->offset;
        if (BPF_CLASS(insn->code) == BPF_JMP) {
            if (poff->inverse)
                set_jmp_offset(b, insn, jt, b->insn - offset);
            else
                set_jmp_offset(b, insn, jf, b->insn - offset);
        }
        poff = poff->next;
    }
    insn = vector_get_data(code, numi + b->insn - 1);
    if (BPF_CLASS(insn->code) == BPF_JMP) {
        set_jmp_offset(b, insn, jt, 0);
        set_jmp_offset(b, insn, jf, 1);
    }
    patch_jmp(b->next, b->insn + numi);
}

static void traverse_blocks(struct block *b)
{
    while (b) {
        if (b->expr1)
            genexpr(b, b->expr1, 0, 0);
        if (b->expr2)
            genexpr(b, b->expr2, 0, 0);
        genjmp(b);
        b->insn = block_insn;
        block_insn = 0;
        b = b->next;
    }
}

void dumpasm(const struct bpf_prog *prog)
{
    for (int i = 0; i < prog->size; i++) {
        switch (BPF_CLASS(prog->bytecode[i].code)) {
        case BPF_LD:
        case BPF_LDX:
            switch (BPF_MODE(prog->bytecode[i].code)) {
            case BPF_IMM:
                printf("%-6s #%d\n", instable[BPF_CLASS(prog->bytecode[i].code) |
                                              BPF_SIZE(prog->bytecode[i].code)],
                       prog->bytecode[i].k);
                break;
            case BPF_ABS:
                printf("%-6s [%d]\n", instable[BPF_CLASS(prog->bytecode[i].code) |
                                               BPF_SIZE(prog->bytecode[i].code)],
                       prog->bytecode[i].k);
                break;
            case BPF_IND:
                printf("%-6s [x+%d]\n", instable[BPF_CLASS(prog->bytecode[i].code) |
                                                 BPF_SIZE(prog->bytecode[i].code)],
                       prog->bytecode[i].k);
                break;
            case BPF_MEM:
                printf("%-6s M[%d]\n", instable[BPF_CLASS(prog->bytecode[i].code) |
                                                BPF_SIZE(prog->bytecode[i].code)],
                       prog->bytecode[i].k);
                break;
            case BPF_MSH:
                printf("%-6s 4 * ([%d] & 0xf)\n", instable[BPF_CLASS(prog->bytecode[i].code)],
                       prog->bytecode[i].k);
                break;
            default:
                break;
            }
            break;
        break;
        case BPF_ST:
        case BPF_STX:
            printf("%-6s M[%d]\n", instable[prog->bytecode[i].code], prog->bytecode[i].k);
            break;
        case BPF_ALU:
            switch (BPF_SRC(prog->bytecode[i].code)) {
            case BPF_K:
                printf("%-6s #0x%x\n", instable[prog->bytecode[i].code], prog->bytecode[i].k);
                break;
            case BPF_X:
                printf("%-6s x\n", instable[BPF_CLASS(prog->bytecode[i].code) |
                                            BPF_OP(prog->bytecode[i].code)]);
                break;
            default:
                break;
            }
            break;
        case BPF_JMP:
            switch (BPF_SRC(prog->bytecode[i].code)) {
            case BPF_K:
                printf("%-6s #0x%x, %d, %d\n", instable[prog->bytecode[i].code],
                       prog->bytecode[i].k, prog->bytecode[i].jt, prog->bytecode[i].jf);
                break;
            case BPF_X:
                printf("%-6s x, %d, %d\n",
                       instable[BPF_CLASS(prog->bytecode[i].code) | BPF_OP(prog->bytecode[i].code)],
                       prog->bytecode[i].jt, prog->bytecode[i].jf);
                break;
            default:
                break;
            }
            break;
        case BPF_RET:
            printf("%-6s #%d\n", instable[prog->bytecode[i].code], prog->bytecode[i].k);
            break;
        case BPF_MISC:
            switch (BPF_MISCOP(prog->bytecode[i].code)) {
            case BPF_TAX:
                printf("tax\n");
                break;
            case BPF_TXA:
                printf("txa\n");
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }
    }
}

struct bpf_prog gencode(struct block *b)
{
    struct bpf_prog prog;
    int sz;
    struct bpf_insn *bc;

    code = vector_init(20);
    memidx = stack_init(BPF_MEMWORDS);
    traverse_blocks(b);
    gen_ret(-1);
    gen_ret(0);
    patch_jmp(b, 0);
    sz = vector_size(code);
    bc = malloc(sz * sizeof(struct bpf_insn));
    for (int i = 0; i < sz; i++)
        bc[i] = *(struct bpf_insn *) vector_get_data(code, i);
    prog.bytecode = bc;
    prog.size = (uint16_t) sz;
    vector_free(code, free);
    stack_free(memidx, NULL);
    return prog;
}
