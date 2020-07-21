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

#define MAXLINE 1000

static struct bpf_parser parser;
static vector_t *bytecode;
static int32_t x;  /* index register */
static int32_t a;  /* accumulator */
static int32_t M[BPF_MEMWORDS]; /* scratch memory store */
static uint32_t pc;

#define get_token() bpf_lex(&parser)
#define bpf_jmp_stm(i, m, jt, jf, k) make_stm(get_opcode(t) | m, jt, jf, k)
#define bpf_stm(i, m, k) make_stm(get_opcode(i) | m, 0, 0, k)

bool bpf_parse_init(char *file)
{
    int fd;
    struct stat st;
    bool ret = false;

    if ((fd = open(file, O_RDONLY)) == -1) {
        perror("open error");
        return false;
    }
    if (fstat(fd, &st) == -1) {
        perror("fstat error");
        goto end;
    }
    memset(&parser, 0, sizeof(parser));
    parser.size = st.st_size;
    parser.line = 1;
    parser.infile = file;
    if ((parser.input.buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
        goto end;
    bytecode = vector_init(10);
    ret = true;

end:
    close(fd);
    return ret;
}

void bpf_parse_free()
{
    munmap(parser.input.buf, parser.size);
    vector_free(bytecode, free);
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
    pc += sizeof(uint64_t);
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

static bool parse_mem(int insn, int reg)
{
    int t;

    if (!parse_abs(&t))
        return false;
    if (!valid_mem_offset(t))
        return false;
    a = M[t];
    bpf_stm(insn, BPF_MEM, reg);
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
        return parse_mem(LD, a);
    } else if (parser.token == '[') {
        if (!parse_offset(LD, a)) {
            error("Unexpected token %c", parser.token);
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
        error("Unexpected token %c", parser.token);
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
        return parse_mem(LDX, x);
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
    error("Unexpected token %c", parser.token);
    return false;
}

static void print_bytecode()
{
    struct bpf_insn *insn;

    for (int i = 0; i < vector_size(bytecode); i++) {
        insn = vector_get_data(bytecode, i);
        printf("0x%x, 0x%x, 0x%x, 0x%x\n", insn->code, insn->jt, insn->jf, insn->k);
    }
}

bool bpf_parse()
{
    parser.input.tok = parser.input.buf;
    parser.input.cur = parser.input.buf;
    parser.input.lim = parser.input.buf + strlen((char *) parser.input.buf) + 1;
    while ((parser.token = get_token()) != 0) {
        switch (parser.token) {
        case LABEL:
            printf("Label: %s\n", parser.val.str);
            free(parser.val.str);
            break;
        case INT:
            printf("Int: %ld\n", parser.val.intval);
            break;
        case LD:
            parse_ld();
            break;
        case LDB:
        case LDH:
            parse_ldbh();
            break;
        case LDX:
            parse_ldx();
            break;
        case ST:
        case STX:
        case ADD:
        case SUB:
        case MUL:
        case DIV:
        case AND:
        case OR:
        case LSH:
        case RSH:
        case JMP:
        case JEQ:
        case JGT:
        case JGE:
        case JSET:
            break;
        case RET:
            parse_ret();
            break;
        case TXA:
        case TAX:
             break;
        default:
            printf("Token: %c\n", parser.token);
            break;
        }
    }
    print_bytecode();
    return true;
}
