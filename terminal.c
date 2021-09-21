#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "terminal.h"

bool get_termsize(struct termsize *sz)
{
    struct winsize size;

    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) < 0)
        return false;
    sz->row = size.ws_row;
    sz->col = size.ws_col;
    return true;
}
