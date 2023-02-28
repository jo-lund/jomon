#ifndef ERROR_H
#define ERROR_H

#include "attributes.h"

/* Fatal error. Print error message and quit */
void err_quit(const char *fmt, ...) PRINTF_FORMAT(1, 2) NORETURN;

/* Fatal error related to a system call. Print error message and quit */
void err_sys(const char *fmt, ...) PRINTF_FORMAT(1, 2) NORETURN;

/* Non-fatal error. Print error message */
void err_msg(const char *fmt, ...) PRINTF_FORMAT(1, 2);

#endif
