#ifndef BPF_LEXER_H
#define BPF_LEXER_H

enum bpf_token {
    ERR_OVERFLOW = -1,
    LABEL = 1,
    INT,
    LD,
    LDH,
    LDB,
    LDX,
    ST,
    STX,
    ADD,
    SUB,
    MUL,
    DIV,
    MOD,
    AND,
    OR,
    XOR,
    LSH,
    RSH,
    JMP,
    JEQ,
    JGT,
    JGE,
    JSET,
    TAX,
    TXA,
    RET
};

#define BPF_NUM_TOKENS 27

struct bpf_parser;

int bpf_lex(struct bpf_parser *parser);

#endif
