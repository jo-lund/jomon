#ifndef PARSE_H
#define PARSE_H

#include <stdbool.h>

struct bpf_input {
    unsigned char *buf;
    unsigned char *lim;
    unsigned char *cur;
    unsigned char *mar; /* the position of the most recent match */
    unsigned char *tok; /* start of current token */
    unsigned char *eof;
};

struct bpf_parser {
    int token;
    union {
        int intval;
        char *str;
    } val;
    struct bpf_input input;
    unsigned int size;
    unsigned int line;
    char *infile;
};


enum bpf_error {
    BPF_SYNTAX_ERROR
};

/* Initialize BPF parser */
bool bpf_parse_init(char *file);

/* Free resources associated with BPF parser */
void bpf_parse_free();

void bpf_parse_setbuf(char *buf, int n);

/*
 * Allocates memory for bytecode that needs to be freed after use, i.e. before
 * calling this function again.
 */
struct bpf_prog bpf_parse();

#endif
