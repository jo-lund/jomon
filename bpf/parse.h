#ifndef PARSE_H
#define PARSE_H

#include <stdbool.h>
#include "lexer.h"

struct bpf_parser {
    int token;
    union {
        long intval;
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

/*
 * Allocates memory for bytecode that needs to be freed after use, i.e. before
 * calling this function again.
 */
struct bpf_prog bpf_parse();

#endif
