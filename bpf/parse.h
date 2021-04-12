#ifndef PARSE_H
#define PARSE_H

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

#endif
