#ifndef FILE_PCAP_H
#define FILE_PCAP_H

enum file_error {
    NO_ERROR,
    FORMAT_ERROR,
    DECODE_ERROR
};

enum file_error read_file(const char *path);

#endif
