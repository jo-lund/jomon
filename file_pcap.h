#ifndef FILE_PCAP_H
#define FILE_PCAP_H

typedef bool (*packet_handler)(unsigned char *buffer, uint32_t n, struct timeval *t);

enum file_error {
    NO_ERROR,
    FORMAT_ERROR,
    DECODE_ERROR
};

/*
 * Read file in pcap format. 'packet_handler' is a callback function that will
 * be called for each packet in the file. The callback function takes two
 * arguments: a buffer containing the encoded packet and the length of the
 * buffer. The caller decides on how to handle the packets. If packet_handler
 * returns false, read_file will return with a DECODE_ERROR.
 */
enum file_error read_file(const char *path, packet_handler f);

#endif
