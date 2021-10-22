#ifndef PACKET_SMTP_H
#define PACKET_SMTP_H

struct smtp_cmd {
    char *command;
    char *params;
};

struct smtp_rsp {
    int code;
    list_t *lines;
};

struct smtp_info {
    bool response;
    char *data;
    uint32_t len;
    union {
        list_t *cmds;
        list_t *rsps;
    };
};

void register_smtp(void);
char *get_smtp_code(int code);

#endif
