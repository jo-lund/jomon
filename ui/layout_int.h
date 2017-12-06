#ifndef LAYOUT_INT_H
#define LAYOUT_INT_H

#include <ncurses.h>
#include "../signal.h"

#define KEY_ESC 27

/* colours on default background  */
#define CYAN COLOR_PAIR(3)
#define GREEN COLOR_PAIR(4)
#define BLUE COLOR_PAIR(5)
#define BROWN COLOR_PAIR(6)
#define MAGENTA COLOR_PAIR(7)
#define RED COLOR_PAIR(8)
#define YELLOW (COLOR_PAIR(6) | A_BOLD)
#define LIGHT_BLUE (BLUE | A_BOLD)
#define PURPLE (MAGENTA | A_BOLD)
#define GREY (COLOR_PAIR(10) | A_BOLD)

#define NUM_SCREENS 3 /* see enum screen_type */

enum screen_type {
    MAIN_SCREEN,
    HELP_SCREEN,
    STAT_SCREEN,
    LABEL_DIALOGUE,
    FILE_DIALOGUE,
    PROGRESS_DIALOGUE
};

enum layer {
    ETHERNET_LAYER,
    ARP,
    LLC,
    SNAP,
    STP,
    IP,
    IGMP,
    ICMP,
    PIM,
    TRANSPORT,
    APPLICATION,
    IPV4_FLAGS,
    STP_FLAGS,
    TCP_FLAGS,
    DNS_FLAGS,
    DNS_RECORDS,
    NBNS_FLAGS,
    NBNS_RECORDS,
    NBDS_FLAGS,
    SMB,
    SMB_FLAGS,
    SNMP_PDU,
    SNMP_VARS,
    SUBLAYER,
    NUM_LAYERS
};

#define SCREEN_REFRESH(o) ((o)->screen_refresh(o))

typedef struct screen {
    enum screen_type type;
    bool focus;
    WINDOW *win;

    /* the function to be called on screen refresh */
    int (*screen_refresh)(struct screen *this);
} screen;

typedef struct {
    bool focus;
    WINDOW *win;
} container;

extern publisher_t *screen_changed_publisher;
extern bool selected[NUM_LAYERS];

typedef void (*free_screen_fn)(void *);

/*
 * Allocates space for the specified screen type and returns it as a singleton
 * object. 'fn' specifies the function that should be called on destruction. If
 * this is NULL the screen destructor, free_screen, will be called.
 *
 * Clients don't need to worry about freeing the object themselves, since this
 * will be handled by layout.
 */
screen *create_screen(enum screen_type type, free_screen_fn fn);

/* Free the memory allocated for screen */
void free_screen(void *s);

/* Allocates space for a new container. Needs to be freed with free_container() */
container *create_container();

/* Free the memory allocated for the container */
void free_container(container *c);

/*
 * Returns the screen with the specified type. Returns NULL if the screen
 * doesn't exist.
 */
screen *get_screen(enum screen_type type);

/* Push the screen on the screen stack */
void push_screen(screen *scr);

/* Pop the screen from the screen stack */
void pop_screen();

/* Return whether the screen stack is empty or not */
bool screen_stack_empty();

/*
 * When the scrollok option is enabled ncurses will wrap long lines at the
 * bottom of the screen. This function will print without line wrapping.
 */
void printnlw(WINDOW *win, char *str, int len, int y, int x, int scrollx);

/*
 * Print text in window with the given attributes. If 'y' and 'x' are -1, it will
 * start to print at the current cursor location.
 */
void printat(WINDOW *win, int y, int x, int attrs, const char *fmt, ...);

/* Create and render the help screen */
screen *help_screen_create();

/* Render the help screen */
void help_screen_render();


#endif
