#ifndef MAIN_SCREEN_H
#define MAIN_SCREEN_H

#include "list_view.h"
#include "screen.h"
#include "vector.h"
#include "rbtree.h"
#include "timer.h"

typedef struct main_screen {
    screen base;
    struct line_info {
        int line_number;
        bool selected;
    } main_line;
    struct subwin_info {
        WINDOW *win;
        int top; /* index to the first line in the subwindow relative to the
                    current page */
        int num_lines;
    } subwindow;
    WINDOW *whdr;
    WINDOW *status;
    list_view *lvw;
    /* next available line, i.e. outy - 1 is the last line printed on the screen */
    int outy;

    /*
     * the number of lines that need to be scrolled to show all the information
     * when inspecting a packet
     */
    int scrolly;
    int scrollx; /* the amount scrolled on the x-axis */
    vector_t *packet_ref;
    bool follow_stream;
    rbtree_t *marked;
    mon_timer_t *timer;
    void (*timer_callback)(void *);
    int input_mode;
    struct input_state *input_goto;
    struct input_state *input_filter;
} main_screen;

struct packet;

main_screen *main_screen_create(void);
void main_screen_init(screen *s);
void main_screen_free(screen *s);
void main_screen_set_interactive(main_screen *ms, bool interactive_mode);
void main_screen_update(main_screen *ms, struct packet *p);

/* refresh the entire pad */
void main_screen_refresh_pad(main_screen *ms);

#endif
