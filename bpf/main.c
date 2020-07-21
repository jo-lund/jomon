#include <stdio.h>
#include <stdlib.h>
#include "parse.h"

int main(int argc, char **argv)
{
    char *infile;

    if (argc != 2) {
        printf("Usage: %s <infile>\n", argv[0]);
        exit(1);
    }
    infile = argv[1];
    if (!bpf_parse_init(infile))
        exit(1);
    bpf_parse();
    bpf_parse_free();
}
