#ifndef LEXER_H
#define LEXER_H

enum token {
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

struct bpf_parser;

int bpf_lex(struct bpf_parser *parser);

#endif
