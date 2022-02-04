#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "parse.h"
#include "bpf_parser.h"
#include "bpf_lexer.h"
#include "bpf.h"
#include "../vector.h"
#include "../hashmap.h"
#include "../hash.h"
#include "../mempool.h"

#define MAXLINE 1000
#define BPF_MAXINSN 4096

struct symbol {
    char *name;
    uint32_t value;
};

static struct bpf_parser parser;
static vector_t *bytecode;
static hashmap_t *symbol_table;

static uint16_t opcodes[] = {
    [LD]   = BPF_LD | BPF_W,
    [LDH]  = BPF_LD | BPF_H,
    [LDB]  = BPF_LD | BPF_B,
    [LDX]  = BPF_LDX | BPF_W,
    [ST]   = BPF_ST,
    [STX]  = BPF_STX,
    [ADD]  = BPF_ALU | BPF_ADD,
    [SUB]  = BPF_ALU | BPF_SUB,
    [MUL]  = BPF_ALU | BPF_MUL,
    [DIV]  = BPF_ALU | BPF_DIV,
    [MOD]  = BPF_ALU | BPF_MOD,
    [AND]  = BPF_ALU | BPF_AND,
    [OR]   = BPF_ALU | BPF_OR,
    [XOR]  = BPF_ALU | BPF_XOR,
    [LSH]  = BPF_ALU | BPF_LSH,
    [RSH]  = BPF_ALU | BPF_RSH,
    [JMP]  = BPF_JMP | BPF_JA,
    [JEQ]  = BPF_JMP | BPF_JEQ,
    [JGT]  = BPF_JMP | BPF_JGT,
    [JGE]  = BPF_JMP | BPF_JGE,
    [JSET] = BPF_JMP | BPF_JSET,
    [TAX]  = BPF_MISC | BPF_TAX,
    [TXA]  = BPF_MISC | BPF_TXA,
    [RET]  = BPF_RET
};

#define get_token() bpf_lex(&parser)
#define bpf_jmp_stm(i, m, jt, jf, k) make_stm(opcodes[i] | (m), jt, jf, k)
#define bpf_stm(i, m, k) make_stm(opcodes[i] | (m), 0, 0, k)

static bool bpf_init(char *file)
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
    symbol_table = hashmap_init(10, hashfnv_string, compare_string);
    hashmap_set_free_data(symbol_table, free);
    ret = true;

end:
    close(fd);
    return ret;
}

static void bpf_free(void)
{
    munmap(parser.input.buf, parser.size);
    vector_free(bytecode, free);
    hashmap_free(symbol_table);
}

static char *get_token_string(int c)
{
    switch (c) {
    case INT:
        return "int";
    case LD:
        return "ld";
    case LDH:
        return "ldh";
    case LDB:
        return "ldb";
    case LDX:
        return "ldx";
    case ST:
        return "st";
    case STX:
        return "stx";
    case ADD:
        return "add";
    case SUB:
        return "sub";
    case MUL:
        return "mul";
    case DIV:
        return "div";
    case AND:
        return "and";
    case OR:
        return "or";
    case XOR:
        return "xor";
    case LSH:
        return "lsh";
    case RSH:
        return "rsh";
    case JMP:
        return "jmp";
    case JEQ:
        return "jeq";
    case JGT:
        return "jgt";
    case JGE:
        return "jge";
    case JSET:
        return "jset";
    case TAX:
        return "tax";
    case TXA:
        return "txa";
    case RET:
        return "ret";
    default:
        return "";
    }
}

static void error(const char *fmt, ...)
{
    char buf[MAXLINE];
    va_list ap;
    int n;

    n = snprintf(buf, MAXLINE, "%s:%d: ", parser.infile, parser.line);
    va_start(ap, fmt);
    vsnprintf(buf + n, MAXLINE - n - 1, fmt, ap);
    va_end(ap);
    strcat(buf, "\n");
    fputs(buf, stderr);
}

static void token_error(int token)
{
    if (token == LABEL)
        error("Syntax error: %s", parser.val.str);
    else if (token < BPF_NUM_TOKENS)
        error("Syntax error: %s", get_token_string(token));
    else
        error("Syntax error: \'%c\'", token);
}

static bool make_stm(uint16_t opcode, uint8_t jt, uint8_t jf, uint32_t k)
{
    if (vector_size(bytecode) >= BPF_MAXINSN) {
        error("Program exceeds max number of instructions: %u", BPF_MAXINSN);
        return false;
    }
    struct bpf_insn *insn = malloc(sizeof(struct bpf_insn));

    insn->code = opcode;
    insn->jt = jt;
    insn->jf = jf;
    insn->k = k;
    vector_push_back(bytecode, insn);
    return true;
}

static inline bool valid_mem_offset(int i)
{
    return i >= 0 && i < BPF_MEMWORDS;
}

static inline bool match(int token)
{
    return (parser.token = get_token()) == token;
}

static bool parse_abs(int *k)
{
    if (!match('[')) {
        error("Expected \'[\' after operand");
        return false;
    }
    if (!match(INT)) {
        error("Expected immediate");
        return false;
    }
    *k = parser.val.intval;
    if (!match(']')) {
        error("Expected \']\'");
        return false;
    }
    return true;
}

static bool parse_offset(int insn)
{
    if (match('x')) {
        if (!match('+'))
            goto error;
        if (!match(INT))
            goto error;
        return bpf_stm(insn, BPF_IND, parser.val.intval);
    } else if (parser.token == INT) {
        return bpf_stm(insn, BPF_ABS, parser.val.intval);
    }

error:
    token_error(parser.token);
    return false;
}

static bool parse_int(int insn, int mode)
{
    int k;
    bool negative = false;

    if (match('-')) {
        negative = true;
        if (!match(INT)) {
            goto error;
        }
    } else if (parser.token != INT) {
        goto error;
    }
    k = negative ? parser.val.intval * -1 : parser.val.intval;
    return bpf_stm(insn, mode, k);

error:
    error("Expected immediate");
    return false;
}

static bool parse_mem(int insn, int mode)
{
    int k;

    if (!parse_abs(&k))
        return false;
    if (!valid_mem_offset(k))
        return false;
    return bpf_stm(insn, mode, k);
}

static bool parse_msh(int insn)
{
    if (parser.val.intval != 4)
        goto error;
    if (!match('*'))
        goto error;
    if (match('(')) {
        int k;

        if (!parse_abs(&k))
            return false;
        if (!match('&'))
            goto error;
        if (!match(INT) && parser.val.intval == 0xf)
            goto error;
        if (!match(')'))
            goto error;

        /*
         * The instruction: ldx  4 * ([k] & 0xf)
         * should use the BPF_B size modifier even though it has no 'b' suffix
         */
        return bpf_stm(insn, BPF_B | BPF_MSH, k);
    }

error:
    token_error(parser.token);
    return false;
}

static bool parse_ld(void)
{
    if (match('#')) {
        return parse_int(LD, BPF_IMM);
    } else if (parser.token == 'M') {
        return parse_mem(LD, BPF_MEM);
    } else if (parser.token == '[') {
        if (!parse_offset(LD))
            return false;
        if (!match(']')) {
            error("Expected \']\'");
            return false;
        }
    }
    return true;
}

static bool parse_ldbh(void)
{
    int insn = parser.token;

    if (!match('[')) {
        error("Expected \'[\' after operand");
        return false;
    }
    if (!parse_offset(insn))
        return false;
    if (!match(']')) {
        error("Expected \']\'");
        return false;
    }
    return true;
}

static bool parse_ldx(void)
{
    if (match('#'))
        return parse_int(LDX, BPF_IMM);
    else if (parser.token == 'M')
        return parse_mem(LDX, BPF_MEM);
    else if (parser.token == INT)
        return parse_msh(LDX);
    return true;
}

static bool parse_ret(void)
{
    if (match('#'))
        return parse_int(RET, BPF_K);
    if (parser.token == 'a' || parser.token == 'A')
        return bpf_stm(RET, BPF_A, 0);
    token_error(parser.token);
    return false;
}

static bool parse_st(void)
{
    int insn = parser.token;

    if (match('M'))
        return parse_mem(insn, 0);
    token_error(parser.token);
    return false;
}

static bool parse_alu(void)
{
    int insn = parser.token;

    if (match('#'))
        return parse_int(insn, BPF_K);
    if (parser.token == 'x')
        return bpf_stm(insn, BPF_X, 0);
    token_error(parser.token);
    return false;
}

static bool parse_label(void)
{
    struct symbol *sym;

    if (!match(':')) {
        if (parser.token != LABEL)
            return true;
        if (!match(':'))
            return true;
    }
    if (hashmap_contains(symbol_table, parser.val.str)) {
        error("Multiple defined label: %s", parser.val.str);
        return false;
    }
    sym = malloc(sizeof(*sym));
    sym->name = parser.val.str;
    sym->value = parser.line - 1;
    hashmap_insert(symbol_table, sym->name, sym);
    return true;
}

static bool parse_jmp(void)
{
    struct symbol *sym;

    if (!match(LABEL)) {
        token_error(parser.token);
        return false;
    }
    if ((sym = hashmap_get(symbol_table, parser.val.str)) == NULL) {
        error("Undefined label: %s", parser.val.str);
        return false;
    }
    if (sym->value < parser.line) {
        error("Backward jumps are not supported");
        return false;
    }
    return bpf_stm(JMP, 0, sym->value - parser.line);
}

static bool parse_cond_jmp(void)
{
    int insn = parser.token;
    int k;
    struct symbol *jt;
    struct symbol *jf;
    unsigned int src;

    if (match('x')) {
        k = 0;
        src = BPF_X;
    } else {
        if (parser.token != '#')
            goto error;
        if (!match(INT))
            goto error;
        k = parser.val.intval;
        src = BPF_K;
    }
    if (!match(','))
        goto error;
    if (!match(LABEL))
        goto error;
    if ((jt = hashmap_get(symbol_table, parser.val.str)) == NULL)
        goto undefined;
    if (!match(','))
        goto error;
    if (!match(LABEL))
        goto error;
    if ((jf = hashmap_get(symbol_table, parser.val.str)) == NULL)
        goto undefined;
    if (jt->value < parser.line || jf->value < parser.line) {
        error("Backward jumps are not supported");
        return false;
    }
    return bpf_jmp_stm(insn, src, jt->value - parser.line, jf->value - parser.line, k);

error:
    token_error(parser.token);
    return false;

undefined:
    error("Undefined label: %s", parser.val.str);
    return false;
}

struct bpf_prog bpf_assemble(char *file)
{
    bool ret = false;
    struct bpf_prog prog = {
        .bytecode = NULL,
        .size = 0
    };
    MEMPOOL_RELEASE enum pool prev = mempool_set(POOL_SHORT);

    if (!bpf_init(file))
        return prog;

    parser.input.tok = parser.input.buf;
    parser.input.cur = parser.input.buf;
    parser.input.lim = parser.input.buf + strlen((char *) parser.input.buf) + 1;
    while ((parser.token = get_token()) != 0) {
        if (parser.token == LABEL) {
            if (!parse_label())
                goto done;
        }
    }
    parser.input.tok = parser.input.buf;
    parser.input.cur = parser.input.buf;
    parser.line = 1;
    while ((parser.token = get_token()) != 0) {
        switch (parser.token) {
        case LABEL:
            if (!match(':')) {
                token_error(parser.token);
                goto done;
            }
            break;
        case INT:
            error("Unexpected integer");
            goto done;
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
        case STX:
            ret = parse_st();
            break;
        case ADD:
        case SUB:
        case MUL:
        case DIV:
        case MOD:
        case AND:
        case OR:
        case XOR:
        case LSH:
        case RSH:
            ret = parse_alu();
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
        case TAX:
            ret = bpf_stm(TAX, 0, 0);
            break;
        case TXA:
            ret = bpf_stm(TXA, 0, 0);
            break;
        default:
            token_error(parser.token);
            goto done;
        }
        if (!ret)
            goto done;
    }
    if (vector_size(bytecode) == 0)
        goto done;

    struct bpf_insn *insn = vector_get(bytecode, vector_size(bytecode) - 1);

    if (BPF_CLASS(insn->code) != BPF_RET) {
        error("Not a valid program");
        goto done;
    }
    int sz = vector_size(bytecode);
    struct bpf_insn *bc = malloc(sz * sizeof(struct bpf_insn));

    for (int i = 0; i < sz; i++)
        bc[i] = * (struct bpf_insn *) vector_get(bytecode, i);
    prog.bytecode = bc;
    prog.size = (uint16_t) sz;

done:
    bpf_free();
    return prog;
}
