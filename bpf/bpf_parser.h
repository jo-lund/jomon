#ifndef BPF_PARSER_H
#define BPF_PARSER_H

/*
 * Allocates memory for bytecode that needs to be freed after use, i.e. before
 * calling this function again.
 */
struct bpf_prog bpf_assemble(char *file);

#endif
