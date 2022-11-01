#ifndef PACKET_SMB_H
#define PACKET_SMB_H

#include <stdint.h>
#include <stdbool.h>
#include "packet.h"

/* SMB commands */
#define SMB_COM_CREATE_DIRECTORY 0x0
#define SMB_COM_DELETE_DIRECTORY 0x1
#define SMB_COM_OPEN 0x2
#define SMB_COM_CREATE 0x3
#define SMB_COM_CLOSE 0x4
#define SMB_COM_FLUSH 0x5
#define SMB_COM_DELETE 0x6
#define SMB_COM_RENAME 0x7
#define SMB_COM_QUERY_INFORMATION 0x8
#define SMB_COM_SET_INFORMATION 0x9
#define SMB_COM_READ 0xa
#define SMB_COM_WRITE 0xb
#define SMB_COM_LOCK_BYTE_RANGE 0xc
#define SMB_COM_UNLOCK_BYTE_RANGE 0xd
#define SMB_COM_CREATE_TEMPORARY 0xe
#define SMB_COM_CREATE_NEW 0xf
#define SMB_COM_CHECK_DIRECTORY 0x10
#define SMB_COM_PROCESS_EXIT 0x11
#define SMB_COM_SEEK 0x12
#define SMB_COM_LOCK_AND_READ 0x13
#define SMB_COM_WRITE_AND_UNLOCK 0x14
#define SMB_COM_READ_RAW 0x1a
#define SMB_COM_READ_MPX 0x1b
#define SMB_COM_READ_MPX_SECONDARY 0x1c
#define SMB_COM_WRITE_RAW 0x1d
#define SMB_COM_WRITE_MPX 0x1e
#define SMB_COM_WRITE_MPX_SECONDARY 0x1f
#define SMB_COM_WRITE_COMPLETE 0x20
#define SMB_COM_QUERY_SERVER 0x21
#define SMB_COM_SET_INFORMATION2 0x22
#define SMB_COM_QUERY_INFORMATION2 0x23
#define SMB_COM_LOCKING_ANDX 0x24
#define SMB_COM_TRANSACTION 0x25

/* flags */
#define SMB_FLAGS_LOCK_AND_READ_OK 0x1
#define SMB_FLAGS_BUF_AVAIL 0x2
#define SMB_FLAGS_CASE_INSENSITIVE 0x8
#define SMB_FLAGS_CANONICALIZED_PATHS 0x10
#define SMB_FLAGS_OPLOCK 0x20
#define SMB_FLAGS_OPBATCH 0x40
#define SMB_FLAGS_REPLY 0x80

/* flags2 */
#define SMB_FLAGS2_LONG_NAMES 0x1
#define SMB_FLAGS2_EAS 0x2
#define SMB_FLAGS2_SMB_SECURITY_SIGNATURE 0x4
#define SMB_FLAGS2_IS_LONG_NAME 0x40
#define SMB_FLAGS2_DFS 0x1000
#define SMB_FLAGS2_PAGING_IO 0x2000
#define SMB_FLAGS2_NT_STATUS 0x4000
#define SMB_FLAGS2_UNICODE 0x8000

struct smb_info {
    uint8_t protocol[4];
    uint8_t command;
    int32_t status;
    uint8_t flags;
    uint16_t flags2;
    uint16_t pidhigh;
    uint8_t security_features[8];
    uint16_t tid;
    uint16_t pidlow;
    uint16_t uid;
    uint16_t mid;
};

char *get_smb_command(uint8_t cmd);
struct packet_flags *get_smb_flags(void);
int get_smb_flags_size(void);
struct packet_flags *get_smb_flags2(void);
int get_smb_flags2_size(void);

/* internal */
void register_smb(void);
packet_error handle_smb(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata);

#endif
