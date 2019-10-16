#ifndef DECODER_REGISTER
#define DECODER_REGISTER

#include "decoder.h"

typedef void (*register_function)();

static register_function decoder_functions[] = {
    register_dns,
    register_nbns,
    register_nbds,
    register_http,
    register_imap,
    register_snmp,
    register_ssdp,
    register_tls
};

#endif
