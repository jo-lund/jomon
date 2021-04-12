#ifndef BPF_PARSER_H
#define BPF_PARSER_H

#include <stdbool.h>

/* Initialize BPF parser */
bool bpf_init(char *file);

/* Free resources associated with BPF parser */
void bpf_free(void);

/*
 * Allocates memory for bytecode that needs to be freed after use, i.e. before
 * calling this function again.
 */
struct bpf_prog bpf_assemble(void);

#endif
