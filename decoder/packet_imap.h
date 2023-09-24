#ifndef PACKET_IMAP
#define PACKET_IMAP

struct imap_info {
    list_t *lines;
};

void register_imap(void);
packet_error handle_imap(struct protocol_info *pinfo, unsigned char *buf, int n,
                         struct packet_data *pdata);

#endif
