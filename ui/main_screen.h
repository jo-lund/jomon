#ifndef MAIN_SCREEN_H
#define MAIN_SCREEN_H

#include "list_view.h"

typedef struct {
    screen base;

    struct line_info {
        int line_number;
        bool selected;
    } main_line;

    struct subwin_info {
        WINDOW *win;
        int top; /* index to the first line in the subwindow relative to the
                    main window, i.e. from 0 to max lines in window */
        int lineno; /* index to the selected line */
        int num_lines;
        int selectionbar; /* index to the selectionbar relative to the pad */
    } subwindow;

    WINDOW *header;
    int selectionbar; /* absolute index to the selection bar, [0, n), where 'n'
                         is the total number of lines */
    list_view *lvw;

    /* next available line, i.e. outy - 1 is the last line printed on the screen */
    int outy;

    /*
     * Index to top of main window. The main screen will be between top + maximum
     * number of lines of the main window, i.e. getmaxy(main_window->win).
     */
    int top;

    /*
     * the number of lines that need to be scrolled to show all the information
     * when inspecting a packet
     */
    int scrolly;

    int scrollx; /* the amount scrolled on the x-axis */
} main_screen;

main_screen *main_screen_create();
void main_screen_init(screen *s);
void main_screen_free(screen *s);
void main_screen_refresh(screen *s);
void main_screen_clear(main_screen *ms);
void main_screen_set_interactive(main_screen *ms, bool interactive_mode);

/* print the buffer to main screen */
void main_screen_update(main_screen *ms, char *buf);

#endif
