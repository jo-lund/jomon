#ifndef LEXER_H
#define LEXER_H

struct bpf_input {
    unsigned char *buf;
    unsigned char *lim;
    unsigned char *cur;
    unsigned char *mar; /* the position of the most recent match */
    unsigned char *tok; /* start of current token */
    unsigned char *eof;
};

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
