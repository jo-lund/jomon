#include <string.h>
#include "util.h"
#include "pcap_lexer.h"
#include "parse.h"
#include "../mempool.h"

#define YYFILL(n) {}
#define YYLIMIT input->lim
#define YYMARKER input->mar
#define TOKENLEN (input->cur - input->tok)

/*!re2c re2c:define:YYCTYPE = "unsigned char"; */

int pcap_lex(struct bpf_parser *parser)
{
    struct bpf_input *input = &parser->input;
    unsigned char *o1, *o2, *o3, *o4;

    if (input->cur == input->eof)
        return PCAP_EOF;

scan:
    if (*input->cur == '\0')
        return PCAP_EOF;
    input->tok = input->cur;

    /*!stags:re2c format = 'unsigned char *@@;'; */

    /*!re2c
      re2c:define:YYCURSOR = input->cur;

      digit = [0-9];
      bin = [01];
      hex = [a-fA-F0-9];
      oct = [0-7];
      ws = [ \t\r];

      /* integers */
      "0" oct* {
        parser->val.intval = getval(input->tok, input->cur, 8);
        return PCAP_INT;
      }

      [1-9] digit* {
          parser->val.intval = getval(input->tok, input->cur, 10);
          return PCAP_INT;
      }
      '0x' hex+ {
          parser->val.intval = gethexval(input->tok + 2, input->cur); /* skip '0x' */
          return PCAP_INT;
      }

      /* primitives */
      "host" { return PCAP_HOST; }
      "net" { return PCAP_NET; }
      "port" { return PCAP_PORT; }
      "portrange" { return PCAP_PORTRANGE; }
      "ether" { return PCAP_ETHER; }
      "fddi" { return PCAP_ETHER; }
      "tr" { return PCAP_TR; }
      "wlan" { return PCAP_WLAN; }
      "ip" { return PCAP_IP; }
      "ip6" { return PCAP_IP6; }
      "arp" { return PCAP_ARP; }
      "rarp" { return PCAP_RARP; }
      "atalk" { return PCAP_ATALK; }
      "aarp" { return PCAP_AARP; }
      "sca" { return PCAP_SCA; }
      "lat" { return PCAP_LAT; }
      "mopdl" { return PCAP_MOPDL; }
      "moprc" { return PCAP_MOPRC; }
      "iso" { return PCAP_ISO; }
      "stp" { return PCAP_STP; }
      "ipx" { return PCAP_IPX; }
      "netbeui" { return PCAP_NETBEUI; }
      "decnet" { return PCAP_DECNET; }
      "llc" { return PCAP_LLC; }
      "tcp" { return PCAP_TCP; }
      "udp" { return PCAP_UDP; }
      "icmp" { return PCAP_ICMP; }
      "icmp6" { return PCAP_ICMP6; }
      "igmp" { return PCAP_IGMP; }
      "igmpr" { return PCAP_IGMPR; }
      "pim" { return PCAP_PIM; }
      "ah" { return PCAP_AH; }
      "esp" { return PCAP_ESP; }
      "vrrp" { return PCAP_VRRP; }
      "gateway" { return PCAP_GATEWAY; }
      "broadcast" { return PCAP_BROADCAST; }
      "multicast" { return PCAP_MULTICAST; }
      "less" { return PCAP_LESS; }
      "greater" { return PCAP_GREATER; }
      "src" { return PCAP_SRC; }
      "dst" { return PCAP_DST; }
      "protochain" { return PCAP_PROTOCHAIN; }

      /* operators */
      "and" { return PCAP_LAND; }
      "&&"  { return PCAP_LAND; }
      "or"  { return PCAP_LOR; }
      "||"  { return PCAP_LOR; }
      "not" { return PCAP_NOT; }
      "!"   { return PCAP_NOT; }
      ">="  { return PCAP_GEQ; }
      "<="  { return PCAP_LEQ; }
      "!="  { return PCAP_NEQ; }
      "<<"  { return PCAP_SHL; }
      ">>"  { return PCAP_SHR; }
      "<"   { return PCAP_LE; }
      ">"   { return PCAP_GT; }
      "="   { return PCAP_EQ; }
      "+"   { return PCAP_ADD; }
      "-"   { return PCAP_SUB; }
      "*"   { return PCAP_MUL; }
      "/"   { return PCAP_DIV; }
      "%"   { return PCAP_MOD; }
      "&"   { return PCAP_AND; }
      "^"   { return PCAP_XOR; }
      "|"   { return PCAP_OR; }
      "["   { return PCAP_LBRACKET; }
      "]"   { return PCAP_RBRACKET; }
      "("   { return PCAP_LPAR; }
      ")"   { return PCAP_RPAR; }

      ":" { return PCAP_COL; }

      /* IPv4 address */
      octet = [0-9] | [1-9][0-9] | [1][0-9][0-9] | [2][0-4][0-9] | [2][5][0-5];
      dot = [.];

      @o1 octet dot @o2 octet dot @o3 octet dot @o4 octet {
          parser->val.intval = getval(o4, input->cur, 10)
              + (getval(o3, o4 - 1, 10) << 8)
              + (getval(o2, o3 - 1, 10) << 16)
              + (getval(o1, o2 - 1, 10) << 24);
          return PCAP_IPADDR;
      }

      /* Ethernet address */
      sep = [:.-];

      (hex{2} sep?){5} hex{2} {
          parser->val.str = mempool_copy0((char *) input->tok, TOKENLEN);
          return PCAP_HWADDR;
      }

      [a-zA-Z][a-zA-Z0-9_]* {
          parser->val.str = mempool_copy0((char *) input->tok, TOKENLEN);
          return PCAP_ID;
      }

      ws+ { goto scan; }

      "\n" { parser->line++; goto scan; }

      * { return -1; }

      /* end of input */
      [\x00] { return PCAP_EOF; }

    */
}
