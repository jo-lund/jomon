#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include "file_pcap.h"
#include "misc.h"
#include "decoder/packet.h"

#define BUFSIZE 128 * 1024
#define LINKTYPE_ETHERNET 1
#define MAGIC_NUMBER 0xa1b2c3d4
#define MAJOR_VERSION 2
#define MINOR_VERSION 4
#define TZ 0
#define SIGFIGS 0

/* global header that starts the pcap file */
typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t thiszone;        /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

/* header for each captured packet */
typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

static bool swap_bytes = false;
static packet_handler pkt_handler;

static int read_buf(unsigned char *buf, size_t len);
static enum file_error read_header(unsigned char *buf, size_t len);
static enum file_error errno_file_error(int err);
static void write_header(unsigned char *buf);
static int write_data(unsigned char *buf, unsigned int len, struct packet *p);

FILE *open_file(const char *path, const char *mode, enum file_error *err)
{
    FILE *fp;

    *err = NO_ERROR;
    if (!(fp = fopen(path, mode))) {
        *err = errno_file_error(errno);
    }
    return fp;
}

enum file_error read_file(FILE *fp, packet_handler f)
{
    unsigned char buf[BUFSIZE];
    enum file_error error = NO_ERROR;
    size_t len;
    int n = 0;

    pkt_handler = f;
    len = fread(buf, sizeof(unsigned char), sizeof(pcap_hdr_t), fp);
    error = read_header(buf, len);
    if (error != NO_ERROR) {
        return error;
    }
    while ((len = fread(buf + n, sizeof(unsigned char), BUFSIZE - n, fp)) > 0) {
        n = read_buf(buf, len + n);
        if (n == -1) {
            error = DECODE_ERROR;
            break;
        }
        if (n > 0) {
            memcpy(buf, buf + BUFSIZE - n, n);
        }
    }
    if (ferror(fp)) error = FORMAT_ERROR;

    return error;
}

/* Read global file header */
enum file_error read_header(unsigned char *buf, size_t len)
{
    pcap_hdr_t *file_header;

    if (len < sizeof(pcap_hdr_t)) return FORMAT_ERROR;

    file_header = (pcap_hdr_t *) buf;
    if (file_header->magic_number == 0xa1b2c3d4) {
        swap_bytes = false;
    } else if (file_header->magic_number == 0xd4c3b2a1) {
        swap_bytes = true;
    } else {
        return FORMAT_ERROR;
    }
    return NO_ERROR;
}

/* Return number of bytes left in buffer or -1 on error */
int read_buf(unsigned char *buf, size_t len)
{
    size_t n = len;

    while (n > 0) {
        uint32_t pkt_len;
        pcaprec_hdr_t *pkt_hdr;
        struct timeval t;

        if (n < sizeof(pcaprec_hdr_t)) {
            return n;
        }
        pkt_hdr = (pcaprec_hdr_t *) buf;
        pkt_len = swap_bytes ? ntohl(pkt_hdr->incl_len) : pkt_hdr->incl_len;
        if (pkt_len > USHRT_MAX) {
            return -1;
        }
        if (pkt_len > n - sizeof(pcaprec_hdr_t)) {
            return n;
        }
        buf += sizeof(pcaprec_hdr_t);
        n -= sizeof(pcaprec_hdr_t);
        t.tv_sec = pkt_hdr->ts_sec;
        t.tv_usec = pkt_hdr->ts_usec;
        if (!pkt_handler(buf, pkt_len, &t)) {
            return -1;
        }
        n -= pkt_len;
        buf += pkt_len;
    }

    return 0;
}

void write_file(FILE *fp, vector_t *packets, progress_update f)
{
    int bufidx = 0;
    unsigned char buf[BUFSIZE];

    write_header(buf);
    bufidx += sizeof(pcap_hdr_t);
    for (int i = 0; i < vector_size(packets); i++) {
        struct packet *p;
        int n;

        p = (struct packet *) vector_get_data(packets, i);
        n = write_data(buf + bufidx, BUFSIZE - bufidx, p);
        if (!n) { /* write buf to file */
            fwrite(buf, sizeof(unsigned char), bufidx, fp);
            bufidx = write_data(buf, BUFSIZE, p);
        } else {
            bufidx += n;
        }
        f(get_packet_size(p));
    }
    if (bufidx) {
        fwrite(buf, sizeof(unsigned char), bufidx, fp);
    }
}

/*
 * Write global pcap header to buffer. We assume buffer is big enough to contain
 * the data.
 */
void write_header(unsigned char *buf)
{
    static pcap_hdr_t header;

    header.magic_number = MAGIC_NUMBER;
    header.version_major = MAJOR_VERSION;
    header.version_minor = MINOR_VERSION;
    header.thiszone = 0;
    header.sigfigs = SIGFIGS;
    header.snaplen = SNAPLEN;
    header.network = LINKTYPE_ETHERNET;
    memcpy(buf, &header, sizeof(pcap_hdr_t));
}

int write_data(unsigned char *buf, unsigned int len, struct packet *p)
{
    if (get_packet_size(p) + sizeof(pcaprec_hdr_t) > len) {
        return 0;
    }

    pcaprec_hdr_t pcap_hdr;

    /* write pcap header */
    pcap_hdr.ts_sec = p->time.tv_sec;
    pcap_hdr.ts_usec = p->time.tv_usec;
    pcap_hdr.incl_len = p->eth.payload_len + ETH_HLEN;
    pcap_hdr.orig_len = p->eth.payload_len + ETH_HLEN;
    memcpy(buf, &pcap_hdr, sizeof(pcaprec_hdr_t));

    /* write packet */
    memcpy(buf + sizeof(pcaprec_hdr_t), p->eth.data, p->eth.payload_len + ETH_HLEN);

    return get_packet_size(p) + sizeof(pcaprec_hdr_t);
}

enum file_error errno_file_error(int err)
{
    switch (err) {
    case EACCES:
        return ACCESS_ERROR;
    case ENOENT:
        return NOT_FOUND_ERROR;
    default:
        return FOPEN_ERROR;
    }
}

char *get_file_error(enum file_error err)
{
    switch (err) {
    case FORMAT_ERROR:
        return "File format not recognized.";
    case DECODE_ERROR:
        return "Error decoding packets.";
    case ACCESS_ERROR:
        return "Operation is not permitted.";
    case NOT_FOUND_ERROR:
        return "File does not exist.";
    case FOPEN_ERROR:
        return "Error opening file.";
    default:
        return "";
    }
}
