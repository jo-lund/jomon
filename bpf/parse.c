#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "parse.h"
#include "lexer.h"
#include "bpf.h"
#include "../vector.h"
#include "../hashmap.h"
#include "../hash.h"

#define MAXLINE 1000

static struct bpf_parser parser;
static vector_t *bytecode;
static int32_t x;  /* index register */
static int32_t a;  /* accumulator */
static int32_t M[BPF_MEMWORDS]; /* scratch memory store */
static hashmap_t *symbol_table;

#define get_token() bpf_lex(&parser)
#define bpf_jmp_stm(i, m, jt, jf, k) make_stm(get_opcode(i) | m, jt, jf, k)
#define bpf_stm(i, m, k) make_stm(get_opcode(i) | m, 0, 0, k)

static inline int add(int x, int y)
{
    return x + y;
}

static inline int sub(int x, int y)
{
    return x - y;
}

static inline int mul(int x, int y)
{
    return x * y;
}

static inline int div2(int x, int y)
{
    return x / y;
}

static inline int and(int x, int y)
{
    return x & y;
}

static inline int or(int x, int y)
{
    return x | y;
}

static inline int xor(int x, int y)
{
    return x ^ y;
}

static inline int lsh(int x, int y)
{
    return x << y;
}

static inline int rsh(int x, int y)
{
    return x >> y;
}

bool bpf_parse_init(char *file)
{
    int fd;
    struct stat st;
    bool ret = false;

    if ((fd = open(file, O_RDONLY)) == -1)
        return false;
    if (fstat(fd, &st) == -1)
        goto end;
    memset(&parser, 0, sizeof(parser));
    parser.size = st.st_size;
    parser.line = 1;
    parser.infile = file;
    if ((parser.input.buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
        goto end;
    bytecode = vector_init(10);
    symbol_table = hashmap_init(10, hash_string, compare_string);
    hashmap_set_free_key(symbol_table, free);
    hashmap_set_free_data(symbol_table, free);
    ret = true;

end:
    close(fd);
    return ret;
}

void bpf_parse_free()
{
    munmap(parser.input.buf, parser.size);
    vector_free(bytecode, free);
    hashmap_free(symbol_table);
}

/* TEMP: Errors need to be handled differently  */
static void error(const char *fmt, ...)
{
    char buf[MAXLINE];
    va_list ap;
    int n;

    n = snprintf(buf, MAXLINE, "%s:%d: error: ", parser.infile, parser.line);
    va_start(ap, fmt);
    vsnprintf(buf + n, MAXLINE - n - 1, fmt, ap);
    va_end(ap);
    strcat(buf, "\n");
    fputs(buf, stderr);
}

static void make_stm(uint16_t opcode, uint8_t jt, uint8_t jf, uint32_t k)
{
    struct bpf_insn *insn = malloc(sizeof(struct bpf_insn));

    insn->code = opcode;
    insn->jt = jt;
    insn->jf = jf;
    insn->k = k;
    vector_push_back(bytecode, insn);
}

static int get_opcode(int insn)
{
    switch (insn) {
    case LD:
        return BPF_LD | BPF_W;
    case LDB:
        return BPF_LD | BPF_B;
    case LDH:
        return BPF_LD | BPF_H;
    case LDX:
        return BPF_LDX | BPF_W;
    case ST:
        return BPF_ST;
    case STX:
        return BPF_STX;
    case ADD:
        return BPF_ALU | BPF_ADD;
    case SUB:
        return BPF_ALU | BPF_SUB;
    case MUL:
        return BPF_ALU | BPF_MUL;
    case DIV:
        return BPF_ALU | BPF_DIV;
    case AND:
        return BPF_ALU | BPF_AND;
    case OR:
        return BPF_ALU | BPF_OR;
    case XOR:
        return BPF_ALU | BPF_XOR;
    case LSH:
        return BPF_ALU | BPF_LSH;
    case RSH:
        return BPF_ALU | BPF_RSH;
    case JMP:
        return BPF_JMP | BPF_JA;
    case JEQ:
        return BPF_JMP | BPF_JEQ;
    case JGT:
        return BPF_JMP | BPF_JGT;
    case JGE:
        return BPF_JMP | BPF_JGE;
    case JSET:
        return BPF_JMP | BPF_JSET;
    case RET:
        return BPF_RET;
    case TXA:
        return BPF_LD | BPF_W;
    case TAX:
        return BPF_LD | BPF_W;
    default:
        return -1;
    }
}

static inline bool valid_mem_offset(int i)
{
    return i >= 0 && i < BPF_MEMWORDS;
}

static inline bool match(int token)
{
    return (parser.token = get_token()) == token;
}

static bool parse_abs(int *reg)
{
    if (!match('[')) {
        error("Expected \'[\' after operand");
        return false;
    }
    if (!match(INT)) {
        error("Expected immediate");
        return false;
    }
    *reg = parser.val.intval;
    if (!match(']')) {
        error("Expected \']\'");
        return false;
    }
    return true;
}

static bool parse_ind(int *reg)
{
    if (!match('x'))
        return false;
    if (!match('+')) {
        error("Syntax error: %c", parser.token);
        return false;
    }
    if (!match(INT)) {
        error("Syntax error: %c", parser.token);
        return false;
    }
    *reg = x + parser.val.intval;
    return true;
}

static bool parse_offset(int insn, int reg)
{
    if (parse_ind(&reg)) {
        bpf_stm(insn, BPF_IND, reg);
    } else if (parser.token == INT) {
        reg = parser.val.intval;
        bpf_stm(insn, BPF_ABS, reg);
    } else {
        return false;
    }
    return true;
}

static bool parse_int(int insn, int reg, int mode)
{
    if (!match(INT)) {
        error("Expected immediate");
        return false;
    }
    reg = parser.val.intval;
    bpf_stm(insn, mode, reg);
    return true;
}

static bool parse_mem(int insn, int reg, int mode, bool load)
{
    int t;

    if (!parse_abs(&t))
        return false;
    if (!valid_mem_offset(t))
        return false;
    if (load)
        reg = M[t];
    else
        M[t] = reg;
    bpf_stm(insn, mode, t);
    return true;
}

static bool parse_msh(int insn, int reg)
{
    if (parser.val.intval != 4)
        goto error;
    if (!match('*'))
        goto error;
    if (match('(')) {
        int t;

        if (!parse_abs(&t))
            return false;
        if (!match('&'))
            goto error;
        if (!match(INT) && parser.val.intval == 0xf)
            goto error;
        reg = 4 * (t & 0xf);
        if (!match(')'))
            goto error;
        bpf_stm(insn, BPF_MSH, reg);
        return true;
    }

error:
    error("Unexpexted token %c\n", parser.token);
    return false;
}

static bool parse_ld()
{
    if (match('#')) {
        return parse_int(LD, a, BPF_IMM);
    } else if (parser.token == 'M') {
        return parse_mem(LD, a, BPF_MEM, true);
    } else if (parser.token == '[') {
        if (!parse_offset(LD, a)) {
            error("Unexpected token: %c", parser.token);
            return false;
        }
        if (!match(']')) {
            error("Expected \']\'");
            return false;
        }
    }
    return true;
}

static bool parse_ldbh()
{
    int insn = parser.token;

    if (!match('[')) {
        error("Expected \'[\' after operand");
        return false;
    }
    if (!parse_offset(insn, a)) {
        error("Unexpected token: %c", parser.token);
        return false;
    }
    if (!match(']')) {
        error("Expected \']\'");
        return false;
    }
    return true;
}

static bool parse_ldx()
{
    if (match('#'))
        return parse_int(LDX, x, BPF_IMM);
    else if (parser.token == 'M')
        return parse_mem(LDX, x, BPF_MEM, true);
    else if (parser.token == INT)
        return parse_msh(LDX, x);
    return true;
}

static bool parse_ret()
{
    if (match('#')) {
        int i = 0;
        return parse_int(RET, i, BPF_K);
    } else if (parser.token == 'a' || parser.token == 'A') {
        bpf_stm(RET, BPF_A, a);
        return true;
    }
    error("Unexpected token: %c", parser.token);
    return false;
}

static bool parse_st()
{
    if (match('M'))
        return parse_mem(ST, a, 0, false);
    error("Unexpected token: %c", parser.token);
    return false;
}

static bool parse_stx()
{
    if (match('M'))
        return parse_mem(STX, x, 0, false);
    error("Unexpected token: %c", parser.token);
    return false;
}

static bool parse_alu(int insn, int alu_op(int, int))
{
    if (match('#')) {
        int t = 0;

        if (parse_int(insn, t, BPF_K)) {
            a = alu_op(a, t);
            return true;
        }
    } else if (parser.token == x) {
        a = alu_op(a, x);
        bpf_stm(insn, BPF_X, 0);
        return true;
    }
    error("Unexpected token: %c", parser.token);
    return false;
}

static bool parse_label()
{
    struct symbol *sym;
    char *str = parser.val.str;

    if (!match(':')) {
        free(str);
        if (parser.token != LABEL)
            return true;
        if (!match(':')) {
            free(str);
            free(parser.val.str);
            return true;
        }
    }
    if (hashmap_contains(symbol_table, parser.val.str)) {
        error("Multiple defined label");
        free(parser.val.str);
        return false;
    }
    sym = malloc(sizeof(*sym));
    sym->name = parser.val.str;
    sym->value = parser.line - 1;
    hashmap_insert(symbol_table, sym->name, sym);
    return true;
}

static bool parse_jmp()
{
    struct symbol *sym;

    if (!match(LABEL)) {
        error("Unexpected token: %c", parser.token);
        return false;
    }
    if ((sym = hashmap_get(symbol_table, parser.val.str)) == NULL) {
        error("Undefined label");
        free(parser.val.str);
        return false;
    }
    bpf_stm(JMP, 0, sym->value - parser.line);
    free(parser.val.str);
    return true;
}

static bool parse_cond_jmp()
{
    int insn = parser.token;
    int t;
    struct symbol *jt;
    struct symbol *jf;

    if (!match('#'))
        goto error;
    if (!match(INT))
        goto error;
    t = parser.val.intval;
    if (!match(','))
        goto error;
    if (!match(LABEL))
        goto error;
    if ((jt = hashmap_get(symbol_table, parser.val.str)) == NULL)
        goto undefined;
    if (!match(','))
        goto error;
    free(parser.val.str);
    if (!match(LABEL))
        goto error;
    if ((jf = hashmap_get(symbol_table, parser.val.str)) == NULL)
        goto undefined;
    bpf_jmp_stm(insn, BPF_K, jt->value - parser.line, jf->value - parser.line, t);
    free(parser.val.str);
    return true;

error:
    free(parser.val.str);
    error("Unexpected token: %c", parser.token);
    return false;

undefined:
    free(parser.val.str);
    error("Undefined label: %s", parser.val.str);
    return false;
}

struct bpf_prog bpf_parse()
{
    bool ret = false;
    struct bpf_prog prog = {
        .bytecode = NULL,
        .size = 0
    };

    parser.input.tok = parser.input.buf;
    parser.input.cur = parser.input.buf;
    parser.input.lim = parser.input.buf + strlen((char *) parser.input.buf) + 1;
    while ((parser.token = get_token()) != 0) {
        if (parser.token == LABEL) {
            if (!parse_label())
                return prog;
        }
    }
    parser.input.tok = parser.input.buf;
    parser.input.cur = parser.input.buf;
    parser.line = 1;
    while ((parser.token = get_token()) != 0) {
        switch (parser.token) {
        case LABEL:
            free(parser.val.str);
            if (!match(':')) {
                error("Unexpected token: %c", parser.token);
                return prog;
            }
            break;
        case INT:
            error("Unexpected integer");
            return prog;
        case LD:
            ret = parse_ld();
            break;
        case LDB:
        case LDH:
            ret = parse_ldbh();
            break;
        case LDX:
            ret = parse_ldx();
            break;
        case ST:
            ret = parse_st();
            break;
        case STX:
            ret = parse_stx();
            break;
        case ADD:
            ret = parse_alu(ADD, add);
            break;
        case SUB:
            ret = parse_alu(SUB, sub);
            break;
        case MUL:
            ret = parse_alu(MUL, mul);
            break;
        case DIV:
            ret = parse_alu(DIV, div2);
            break;
        case AND:
            ret = parse_alu(AND, and);
            break;
        case OR:
            ret = parse_alu(OR, or);
            break;
        case XOR:
            ret = parse_alu(XOR, xor);
            break;
        case LSH:
            ret = parse_alu(LSH, lsh);
            break;
        case RSH:
            ret = parse_alu(RSH, rsh);
            break;
        case JMP:
            ret = parse_jmp();
            break;
        case JEQ:
        case JGT:
        case JGE:
        case JSET:
            ret = parse_cond_jmp();
            break;
        case RET:
            ret = parse_ret();
            break;
        case TXA:
            a = x;
            break;
        case TAX:
            x = a;
            break;
        default:
            error("Unexpected token: %c", parser.token);
            return prog;
        }
        if (!ret)
            return prog;
    }
    int sz = vector_size(bytecode);
    struct bpf_insn *bc = malloc(sz * sizeof(struct bpf_insn));

    for (int i = 0; i < sz; i++)
        bc[i] = * (struct bpf_insn *) vector_get_data(bytecode, i);
    prog.bytecode = bc;
    prog.size = (uint16_t) sz;
    return prog;
}
