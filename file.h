#ifndef FILE_PCAP_H
#define FILE_PCAP_H

#include "vector.h"
#include "interface.h"

typedef void (*progress_update)(int i);

enum file_error {
    NO_ERROR,
    FORMAT_ERROR,
    LINK_ERROR,
    VERSION_ERROR,
    DECODE_ERROR,
    ACCESS_ERROR,
    NOT_FOUND_ERROR,
    FOPEN_ERROR,
    FILE_EXIST_ERROR
};

/*
 * Open a file for reading/writing based on mode (see fopen). If no errors it
 * returns a pointer to FILE that needs to be closed by the caller. Otherwise
 * 'err' will be set indicating the error and NULL is returned.
 */
FILE *file_open(const char *path, const char *mode, enum file_error *err);

/* Get a string representing the error */
char *file_error(enum file_error err);

/*
 * Read file in pcap format. 'packet_handler' is a callback function that will
 * be called for each packet in the file. The callback function takes three
 * arguments: a buffer containing the encoded packet, the length of the buffer,
 * and a pointer to the timestamp for the packet. The caller decides on how to
 * handle the packets. If packet_handler returns false, read_file will return
 * with a DECODE_ERROR.
 */
enum file_error file_read(iface_handle_t *handle, FILE *fp, packet_handler f);

/* Write packets to file in pcap format */
void file_write_pcap(FILE *fp, vector_t *packets, progress_update fn);

/* Write packets to file in ascii */
void file_write_ascii(FILE *fp, vector_t *packets, progress_update fn);

/* Write the raw bytes in packets to file */
void file_write_raw(FILE *fp, vector_t *packets, progress_update fn);


#endif
