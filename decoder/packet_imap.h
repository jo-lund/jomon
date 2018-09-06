#ifndef PACKET_IMAP
#define PACKET_IMAP

struct imap_info {
    list_t *lines;
};

struct application_info;

packet_error handle_imap(unsigned char *buf, int n, struct application_info *adu);

#endif
