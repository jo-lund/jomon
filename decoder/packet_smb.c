#include <string.h>
#include "packet_smb.h"
#include "packet.h"
#include "../util.h"

#define SMB_HDR_LEN 32

static char *smb_cmds[] = {
    "Create directory", "Delete directory", "Open", "Create", "Close", "Flush", "Delete",
    "Rename", "Query information", "Set information", "Read", "Write", "Lock byte range",
    "Unlock byte range", "Create temporary", "Create new", "Check directory",
    "Process exit", "Seek", "Lock and read", "Write and unlock", "", "", "", "", "",
    "Read raw", "Multiplexed block read", "Multiplex block read, secondary request",
    "Write raw","Multiplexed block write", "Multiplex block write, secondary request",
    "Raw block write, final response", "Query server", "Set an extended set of file attributes",
    "Get an extended set of file attributes", "Lock multiple byte ranges",
    "Transaction"
};

static struct packet_flags smb_flags[] = {
    { "Reply", 1, NULL },
    { "Batch oplock", 1, NULL },
    { "Exclusive oplock", 1, NULL },
    { "Canonicalized paths", 1, NULL },
    { "Case insensitive", 1, NULL },
    { "Reserved", 1, NULL },
    { "Buf available", 1, NULL },
    { "Lock and read ok", 1, NULL }
};

static struct packet_flags smb_flags2[] = {
    { "Unicode", 1, NULL },
    { "NT status", 1, NULL},
    { "Read if execute", 1, NULL },
    { "Distributed File System", 1, NULL },
    { "Reserved", 5, NULL },
    { "Is long name", 1, NULL },
    { "Security signature", 1, NULL },
    { "Extended attributes", 1, NULL },
    { "May contain long names", 1, NULL }
};

static struct protocol_info smb_prot = {
    .short_name = "SMB",
    .long_name = "Server Message Block",
    .decode = handle_smb,
    .print_pdu = NULL,
};

void register_smb(void)
{
    register_protocol(&smb_prot, PORT, SMB);
}

packet_error handle_smb(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    if (n < SMB_HDR_LEN)
        return UNK_PROTOCOL;
    if (buffer[0] != 0xff || buffer[1] != 'S' ||
        buffer[2] != 'M' || buffer[3] != 'B')
        return UNK_PROTOCOL;

    struct smb_info *smb;

    pinfo->num_packets++;
    pinfo->num_bytes += n;
    smb = mempool_alloc(sizeof(struct smb_info));
    pdata->len = n;
    memcpy(smb->protocol, buffer, 4);
    smb->command = buffer[4];
    smb->status = (int32_t) get_uint32le(buffer + 5);
    smb->flags = buffer[9];
    smb->flags2 = get_uint16le(buffer + 10);
    smb->pidhigh = get_uint16le(buffer + 12);
    memcpy(smb->security_features, buffer + 14, 8);
    buffer += 24; /* 22 + 2 bytes that are reserved */
    smb->tid = get_uint16le(buffer);
    smb->pidlow = get_uint16le(buffer + 2);
    smb->uid = get_uint16le(buffer + 4);
    smb->mid = get_uint16le(buffer + 6);
    return NO_ERR;
}

char *get_smb_command(uint8_t cmd)
{
    if (cmd < ARRAY_SIZE(smb_cmds)) {
        return smb_cmds[cmd];
    }
    return NULL;
}

struct packet_flags *get_smb_flags()
{
    return smb_flags;
}

int get_smb_flags_size()
{
    return ARRAY_SIZE(smb_flags);
}

struct packet_flags *get_smb_flags2()
{
    return smb_flags2;
}

int get_smb_flags2_size()
{
    return ARRAY_SIZE(smb_flags2);
}
