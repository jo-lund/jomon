#include <string.h>
#include "bpf_lexer.h"
#include "parse.h"
#include "util.h"
#include "../mempool.h"

#define YYFILL(n) {}
#define YYLIMIT input->lim
#define YYMARKER input->mar
#define TOKENLEN (input->cur - input->tok)

/*!re2c re2c:define:YYCTYPE = "unsigned char"; */

int bpf_lex(struct bpf_parser *parser)
{
    struct bpf_input *input = &parser->input;
    bool error;

    if (input->eof && input->cur == input->eof)
        return 0;

scan:
    if (*input->cur == '\0')
        return 0;
    input->tok = input->cur;

    /*!re2c
      re2c:define:YYCURSOR = input->cur;

      digit = [0-9];
      bin = [01];
      hex = [a-fA-F0-9];
      oct = [0-7];
      ws = [ \t\r];

      /* integers */
    "0" oct* {
        parser->val.intval = getval(input->tok, input->cur, 8, &error);
        if (parser->val.intval == -1 && error)
            return ERR_OVERFLOW;
        return INT;
    }
    [1-9] digit* {
        parser->val.intval = getval(input->tok, input->cur, 10, &error);
        if (parser->val.intval == -1 && error)
            return ERR_OVERFLOW;
        return INT;
    }
    '0x' hex+ {
        parser->val.intval = gethexval(input->tok + 2, input->cur, &error); /* skip '0x' */
        if (parser->val.intval == -1 && error)
            return ERR_OVERFLOW;
        return INT;
    }

    /* instructions */
    "ld"   { return LD; }
    "ldb"  { return LDB; }
    "ldh"  { return LDH; }
    "ldx"  { return LDX; }
    "st"   { return ST; }
    "stx"  { return STX; }
    "add"  { return ADD; }
    "sub"  { return SUB; }
    "mul"  { return MUL; }
    "div"  { return DIV; }
    "mod"  { return MOD; }
    "and"  { return AND; }
    "or"   { return OR; }
    "lsh"  { return LSH; }
    "rsh"  { return RSH; }
    "jmp"  { return JMP; }
    "jeq"  { return JEQ; }
    "jgt"  { return JGT; }
    "jge"  { return JGE; }
    "jset" { return JSET; }
    "ret"  { return RET; }
    "txa"  { return TXA; }
    "tax"  { return TAX; }

    /* registers/scratch memory store */
    [axM] { return input->tok[0]; }

    [a-zA-Z][a-zA-Z0-9_]* {
        parser->val.str = mempool_copy0((char *) input->tok, TOKENLEN);
        return LABEL;
    }

    [:+*[\]#,()&-] { return input->tok[0]; }

    ws+ { goto scan; }

    "\n" { parser->line++; goto scan; }

    ";" (. \ [\n\x00])* { goto scan; }

    * { return -1; }

    /* end of input */
    [\x00] { return 0; }

    */

    return 0;
}
