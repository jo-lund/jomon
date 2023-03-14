#ifndef SCREEN_H
#define SCREEN_H

#include <stdbool.h>
#include <ncurses.h>

/*
 * Convenience macros that will call the functions defined in screen_operations.
 * The argument 'o' is a pointer to the screen.
 */
#define SCREEN_INIT(o) ((o)->op->screen_init(o))
#define SCREEN_FREE(o) ((o)->op->screen_free(o))
#define SCREEN_REFRESH(o) ((o)->op->screen_refresh(o))
#define SCREEN_GET_INPUT(o) ((o)->op->screen_get_input(o))
#define SCREEN_GOT_FOCUS(o, s) ((o)->op->screen_got_focus(o, s))
#define SCREEN_LOST_FOCUS(o, s) ((o)->op->screen_lost_focus(o, s))
#define SCREEN_GET_DATA_SIZE(o) ((o)->op->screen_get_data_size(s))
#define SCREEN_ON_BACK(o) ((o)->op->screen_on_back(o))

#define SCREEN_DEFAULTS .screen_init = screen_init, \
        .screen_free = screen_free,                 \
        .screen_refresh = screen_refresh,           \
        .screen_get_input = screen_get_input

#define SCREEN_OPS(...) ((struct screen_operations)   \
        { SCREEN_DEFAULTS, __VA_ARGS__ })

#define HEADER_HEIGHT 5

typedef struct {
    char *txt;
    int width;
    int order;
} screen_header;

typedef struct screen {
    bool focus;
    WINDOW *win;
    bool have_selectionbar; /* defined if the screen has a selectionbar */
    int selectionbar; /* absolute index to the selection bar, [0, n),
                         where 'n' is the total number of lines */
    bool show_selectionbar;
    int top; /* absolute index to top of screen */
    int lines;
    int page;
    int num_pages;
    bool refreshing;
    bool fullscreen;
    bool resize;
    screen_header *header;
    unsigned int header_size;
    unsigned int hpos;
    bool tab_active;
    bool hide_selectionbar;  /* hide selectionbar when tab is active */
    struct screen_operations *op;
} screen;

typedef struct screen_operations {
    void (*screen_init)(screen *s);
    void (*screen_free)(screen *s);
    void (*screen_refresh)(screen *s);
    void (*screen_get_input)(screen *s);
    void (*screen_got_focus)(screen *s, screen *oldscr);
    void (*screen_lost_focus)(screen *s, screen *newscr);
    unsigned int (*screen_get_data_size)(screen *s);
    void (*screen_on_back)(screen *s);
} screen_operations;

enum header_order {
    HDR_INCREASING,
    HDR_DECREASING
};

/* Create a screen object */
screen *screen_create(screen_operations *op);

/* Default screen constructor */
void screen_init(screen *s);

/* Default screen destructor */
void screen_free(screen *s);

/* Default function called on screen refresh */
void screen_refresh(screen *s);

/* Default function called on key input */
void screen_get_input(screen *s);

void screen_render_header_focus(screen *s, WINDOW *whdr);
void screen_update_order(screen *s, void *data, int size,
                         int (*cmp_elem)(const void *, const void *, void *));
#endif
