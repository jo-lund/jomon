#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "file_pcap.h"
#include "error.h"
#include "packet.h"
#include "vector.h"

#define BUFSIZE 65535
#define LINKTYPE_ETHERNET 1

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

static bool big_endian = false;

static int read_buf(unsigned char *buf, size_t len);
static enum file_error read_header(unsigned char *buf, size_t len);

enum file_error read_file(const char *path)
{
    FILE *fp;
    unsigned char *buf;
    enum file_error error = NO_ERROR;
    size_t len;
    int n = 0;

    if (!(fp = fopen(path, "r"))) {
        err_sys("fopen error");
    }
    buf = malloc(BUFSIZE);
    len = fread(buf, sizeof(unsigned char), sizeof(pcap_hdr_t), fp);
    error = read_header(buf, len);
    if (error != NO_ERROR) {
        fclose(fp);
        free(buf);
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
    fclose(fp);
    free(buf);

    return error;
}

/* Read global file header */
enum file_error read_header(unsigned char *buf, size_t len)
{
    pcap_hdr_t *file_header;

    if (len < sizeof(pcap_hdr_t)) return FORMAT_ERROR;

    file_header = (pcap_hdr_t *) buf;
    if (file_header->magic_number == 0xa1b2c3d4) {
        big_endian = false;
    } else if (file_header->magic_number == 0xd4c3b2a1) {
        big_endian = true;
    } else {
        return FORMAT_ERROR;
    }
    return NO_ERROR;
}

/* Return number of bytes left in buffer or -1 on error */
int read_buf(unsigned char *buf, size_t len)
{
    int n = len;

    while (n > 0) {
        struct packet *p;
        uint32_t pkt_len;
        pcaprec_hdr_t *pkt_hdr;

        if (n < sizeof(pcaprec_hdr_t)) {
            return n;
        }
        pkt_hdr = (pcaprec_hdr_t *) buf;
        pkt_len = big_endian ? ntohl(pkt_hdr->incl_len) : pkt_hdr->incl_len;
        if (pkt_len > n - sizeof(pcaprec_hdr_t)) {
            return n;
        }
        buf += sizeof(pcaprec_hdr_t);
        n -= sizeof(pcaprec_hdr_t);
        if (decode_packet(buf, pkt_len, &p) == -1) {
            return -1;
        }
        vector_push_back(p);
        n -= pkt_len;
        buf += pkt_len;
    }

    return 0;
}
