#ifndef ERROR_H
#define ERROR_H

/* Fatal error. Print error message and quit */
void err_quit(const char *fmt, ...);

/* Fatal error related to a system call. Print error message and quit */
void err_sys(const char *fmt, ...);

/* Non-fatal error. Print error message */
void err_msg(const char *fmt, ...);

#endif
