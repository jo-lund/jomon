#include <stdio.h>
#include <stdlib.h>
#include "parse.h"
#include "bpf.h"

static void print_bytecode(struct bpf_prog bpf)
{
    for (int i = 0; i < bpf.size; i++) {
        printf("0x%x, 0x%x, 0x%x, 0x%x\n", bpf.bytecode[i].code, bpf.bytecode[i].jt,
               bpf.bytecode[i].jf, bpf.bytecode[i].k);
    }
}

int main(int argc, char **argv)
{
    char *infile;
    struct bpf_prog bpf;

    if (argc != 2) {
        printf("Usage: %s <infile>\n", argv[0]);
        exit(1);
    }
    infile = argv[1];
    if (!bpf_parse_init(infile))
        exit(1);
    bpf = bpf_parse();
    if (bpf.size)
        print_bytecode(bpf);
    free(bpf.bytecode);
    bpf_parse_free();
}
