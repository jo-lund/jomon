#include "bpf.h"
#include "../util.h"

int bpf_run_filter(struct bpf_prog bpf, unsigned char *buf, uint32_t n)
{
    uint32_t a = 0; /* accumulator */
    uint32_t x = 0; /* index register */
    uint32_t pc = 0;
    uint32_t M[BPF_MEMWORDS]; /* scratch memory store */
    static void *dispatch_table[] = {
        [BPF_LD | BPF_W | BPF_ABS] = &&ld_abs,
        [BPF_LD | BPF_H | BPF_ABS] = &&ldh_abs,
        [BPF_LD | BPF_B | BPF_ABS] = &&ldb_abs,
        [BPF_LD | BPF_W | BPF_IND] = &&ld_ind,
        [BPF_LD | BPF_H | BPF_IND] = &&ldh_ind,
        [BPF_LD | BPF_B | BPF_IND] = &&ldb_ind,
        [BPF_LD | BPF_W | BPF_LEN] = &&ld_len,
        [BPF_LD | BPF_IMM] = &&ld_imm,
        [BPF_LD | BPF_MEM] = &&ld_mem,
        [BPF_LDX | BPF_W | BPF_IMM] = &&ldx_imm,
        [BPF_LDX | BPF_W | BPF_MEM] = &&ldx_mem,
        [BPF_LDX | BPF_W | BPF_LEN] = &&ldx_len,
        [BPF_LDX | BPF_B | BPF_MSH] = &&ldx_msh,
        [BPF_ST] = &&st,
        [BPF_STX] = &&stx,
        [BPF_ALU | BPF_ADD | BPF_K] = &&add_k,
        [BPF_ALU | BPF_SUB | BPF_K] = &&sub_k,
        [BPF_ALU | BPF_MUL | BPF_K] = &&mul_k,
        [BPF_ALU | BPF_DIV | BPF_K] = &&div_k,
        [BPF_ALU | BPF_MOD | BPF_K] = &&mod_k,
        [BPF_ALU | BPF_AND | BPF_K] = &&and_k,
        [BPF_ALU | BPF_OR | BPF_K] = &&or_k,
        [BPF_ALU | BPF_XOR | BPF_K] = &&xor_k,
        [BPF_ALU | BPF_LSH | BPF_K] = &&lsh_k,
        [BPF_ALU | BPF_RSH | BPF_K] = &&rsh_k,
        [BPF_ALU | BPF_ADD | BPF_X] = &&add_x,
        [BPF_ALU | BPF_SUB | BPF_X] = &&sub_x,
        [BPF_ALU | BPF_MUL | BPF_X] = &&mul_x,
        [BPF_ALU | BPF_DIV | BPF_X] = &&div_x,
        [BPF_ALU | BPF_MOD | BPF_X] = &&mod_x,
        [BPF_ALU | BPF_AND | BPF_X] = &&and_x,
        [BPF_ALU | BPF_OR | BPF_X] = &&or_x,
        [BPF_ALU | BPF_XOR | BPF_X] = &&xor_x,
        [BPF_ALU | BPF_LSH | BPF_X] = &&lsh_x,
        [BPF_ALU | BPF_RSH | BPF_X] = &&rsh_x,
        [BPF_ALU | BPF_NEG] = &&neg,
        [BPF_JMP | BPF_JA] = &&jmp,
        [BPF_JMP | BPF_JEQ | BPF_K] = &&jeq_k,
        [BPF_JMP | BPF_JGT | BPF_K] = &&jgt_k,
        [BPF_JMP | BPF_JGE | BPF_K] = &&jge_k,
        [BPF_JMP | BPF_JSET | BPF_K] = &&jset_k,
        [BPF_JMP | BPF_JEQ | BPF_X] = &&jeq_x,
        [BPF_JMP | BPF_JGT | BPF_X] = &&jgt_x,
        [BPF_JMP | BPF_JGE | BPF_X] = &&jge_x,
        [BPF_JMP | BPF_JSET | BPF_X] = &&jset_x,
        [BPF_RET | BPF_A] = &&ret_a,
        [BPF_RET | BPF_K] = &&ret_k,
        [BPF_MISC | BPF_TAX] = &&tax,
        [BPF_MISC | BPF_TXA] = &&txa
    };

    memset(M, 0, sizeof(M));
    goto *dispatch_table[bpf.bytecode[pc++].code];

ld_abs:
    if (bpf.bytecode[pc-1].k > n)
        return 0;
    a = get_uint32be(buf + bpf.bytecode[pc-1].k);
    goto *dispatch_table[bpf.bytecode[pc++].code];

ldh_abs:
    if (bpf.bytecode[pc-1].k > n)
        return 0;
    a = get_uint16be(buf + bpf.bytecode[pc-1].k);
    goto *dispatch_table[bpf.bytecode[pc++].code];

ldb_abs:
    if (bpf.bytecode[pc-1].k > n)
        return 0;
    a = buf[bpf.bytecode[pc-1].k];
    goto *dispatch_table[bpf.bytecode[pc++].code];

ld_ind:
    if (x + bpf.bytecode[pc-1].k > n)
        return 0;
    a = get_uint32be(buf + x + bpf.bytecode[pc-1].k);
    goto *dispatch_table[bpf.bytecode[pc++].code];

ldh_ind:
    if (x + bpf.bytecode[pc-1].k > n)
        return 0;
    a = get_uint16be(buf + x + bpf.bytecode[pc-1].k);
    goto *dispatch_table[bpf.bytecode[pc++].code];

ldb_ind:
    if (x + bpf.bytecode[pc-1].k > n)
        return 0;
    a = buf[x + bpf.bytecode[pc-1].k];
    goto *dispatch_table[bpf.bytecode[pc++].code];

ld_len:
    a = n;
    goto *dispatch_table[bpf.bytecode[pc++].code];

ld_imm:
    a = bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

ld_mem:
    a = M[bpf.bytecode[pc-1].k];
    goto *dispatch_table[bpf.bytecode[pc++].code];

ldx_imm:
    x = bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

ldx_mem:
    x = M[bpf.bytecode[pc-1].k];
    goto *dispatch_table[bpf.bytecode[pc++].code];

ldx_len:
    x = n;
    goto *dispatch_table[bpf.bytecode[pc++].code];

ldx_msh:
    if (bpf.bytecode[pc-1].k > n)
        return 0;
    x = 4 * (buf[bpf.bytecode[pc-1].k] & 0xf);
    goto *dispatch_table[bpf.bytecode[pc++].code];

st:
    M[bpf.bytecode[pc-1].k] = a;
    goto *dispatch_table[bpf.bytecode[pc++].code];

stx:
    M[bpf.bytecode[pc-1].k] = x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

add_k:
    a += bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

sub_k:
    a -= bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

mul_k:
    a *= bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

div_k:
    if (bpf.bytecode[pc-1].k == 0)
        return 0;
    a /= bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

mod_k:
    if (bpf.bytecode[pc-1].k == 0)
        return 0;
    a %= bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

and_k:
    a &= bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

or_k:
    a |= bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

xor_k:
    a ^= bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

lsh_k:
    a <<= bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

rsh_k:
    a >>= bpf.bytecode[pc-1].k;
    goto *dispatch_table[bpf.bytecode[pc++].code];

add_x:
    a += x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

sub_x:
    a -= x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

mul_x:
    a *= x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

div_x:
    if (x == 0)
        return 0;
    a /= x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

mod_x:
    if (x == 0)
        return 0;
    a %= x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

and_x:
    a &= x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

or_x:
    a |= x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

xor_x:
    a ^= x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

lsh_x:
    a <<= x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

rsh_x:
    a >>= x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

neg:
    a = -a;
    goto *dispatch_table[bpf.bytecode[pc++].code];

jmp:
    pc = bpf.bytecode[pc-1].k + pc;
    goto *dispatch_table[bpf.bytecode[pc++].code];

jeq_k:
    pc = (a == bpf.bytecode[pc-1].k) ? bpf.bytecode[pc-1].jt + pc : bpf.bytecode[pc-1].jf + pc;
    goto *dispatch_table[bpf.bytecode[pc++].code];

jgt_k:
    pc = (a > bpf.bytecode[pc-1].k) ? bpf.bytecode[pc-1].jt + pc : bpf.bytecode[pc-1].jf + pc;
    goto *dispatch_table[bpf.bytecode[pc++].code];

jge_k:
    pc = (a >= bpf.bytecode[pc-1].k) ? bpf.bytecode[pc-1].jt + pc : bpf.bytecode[pc-1].jf + pc;
    goto *dispatch_table[bpf.bytecode[pc++].code];

jset_k:
    pc = (a & bpf.bytecode[pc-1].k) ? bpf.bytecode[pc-1].jt + pc: bpf.bytecode[pc-1].jf + pc;
    goto *dispatch_table[bpf.bytecode[pc++].code];

jeq_x:
    pc = (a == x) ? bpf.bytecode[pc-1].jt + pc : bpf.bytecode[pc-1].jf + pc;
    goto *dispatch_table[bpf.bytecode[pc++].code];

jgt_x:
    pc = (a > x) ? bpf.bytecode[pc-1].jt + pc : bpf.bytecode[pc-1].jf + pc;
    goto *dispatch_table[bpf.bytecode[pc++].code];

jge_x:
    pc = (a >= x) ? bpf.bytecode[pc-1].jt + pc : bpf.bytecode[pc-1].jf + pc;
    goto *dispatch_table[bpf.bytecode[pc++].code];

jset_x:
    pc = (a & x) ? bpf.bytecode[pc-1].jt + pc : bpf.bytecode[pc-1].jf + pc;
    goto *dispatch_table[bpf.bytecode[pc++].code];

tax:
    x = a;
    goto *dispatch_table[bpf.bytecode[pc++].code];

txa:
    a = x;
    goto *dispatch_table[bpf.bytecode[pc++].code];

ret_a:
    return a;

ret_k:
    return bpf.bytecode[pc-1].k;
}
