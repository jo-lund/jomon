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

bool bpf_parse_init(char *file);
void bpf_parse_free();
bool bpf_parse();

#endif
