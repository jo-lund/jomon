#ifndef PACKET_IMAP
#define PACKET_IMAP

struct imap_info {
    list_t *lines;
};

struct application_info;

void register_imap();
packet_error handle_imap(struct protocol_info *pinfo, unsigned char *buf, int n,
                         void *data);

#endif
