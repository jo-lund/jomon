#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include "parse.h"
#include "bpf.h"
#include "pcap_lexer.h"

#define get_token() pcap_lex(&parser)

static struct bpf_parser parser;

struct bpf_prog pcap_compile(char *filter)
{
    struct bpf_prog prog = {
        .bytecode = NULL,
        .size = 0
    };

    return prog;
}
