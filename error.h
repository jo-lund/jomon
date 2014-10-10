/* Fatal error. Print error message and quit */
void err_quit(const char *fmt, ...);

/* Fatal error related to a system call. Print error message and quit */
void err_sys(const char *fmt, ...);

/* Non-fatal error. Print error message */
void err_msg(const char *fmt, ...);

/* Print error message to standard error */
static void print_error(const char *fmt, int error, va_list ap);
