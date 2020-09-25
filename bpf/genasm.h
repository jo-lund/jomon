#ifndef GENASM_H
#define GENASM_H

struct block;

struct bpf_prog gencode(struct block *b);
void dumpasm(const struct bpf_prog *prog);

#endif
