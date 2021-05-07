#ifndef PACKET_SMTP_H
#define PACKET_SMTP_H

struct smtp_info {
    char *start_line;
    bool response;
    char *data;
    uint32_t len;
    union {
        struct {
            char *command;
            char *params;
        } cmd;
        struct {
            int code;
            list_t *lines;
        } rsp;
    };
};

void register_smtp(void);
char *get_smtp_code(int code);

#endif
