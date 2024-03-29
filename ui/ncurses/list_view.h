#ifndef LIST_VIEW_H
#define LIST_VIEW_H

#include <stdbool.h>
#include <stdint.h>
#include <ncurses.h>
#include "list.h"
#include "attributes.h"

/*
 * Convenience macros that will call the functions defined in list_view.
 * The first argument, 'o', is a pointer to the list_view.
 */
#define LV_ADD_HEADER(o, text, expanded, data) (o)->add_header(o, text, expanded, data)
#define LV_ADD_SUB_HEADER(o, w, expanded, data, text, ...)          \
    (o)->add_sub_header(o, w, expanded, data, text, ## __VA_ARGS__)
#define LV_ADD_TEXT_ELEMENT(o, h, text, ...)                    \
    (o)->add_text_element(o, h, A_NORMAL, text, ## __VA_ARGS__)
#define LV_ADD_TEXT_ATTR(o, h, attr, text, ...)             \
    (o)->add_text_element(o, h, attr, text, ## __VA_ARGS__)
#define LV_SET_EXPANDED(o, i, expanded) (o)->set_expanded(o, i, expanded)
#define LV_GET_EXPANDED(o, i) (o)->get_expanded(o, i)
#define LV_GET_DATA(o, i) (o)->get_data(o, i)
#define LV_GET_ATTR(o, i) (o)->get_attribute(o, i)
#define LV_RENDER(o, win) (o)->render(o, win)

typedef struct {
    char *txt;
    uint32_t attr;
    uint16_t type;
} list_view_item;

typedef struct lvh {
    list_view_item base;
    struct lvh *parent;
    bool expanded;
    int32_t data;
    list_t *subwidgets;
} list_view_header;

typedef struct lw {
    int num_elements; /* number of elements in the list_view */
    int size; /* number of lines that the list_view will show */
    list_t *widgets;

    /*
     * Adds a header element to the list view. The header will be prefixed by '+'
     * or '-' depending on whether it is expanded or not.
     */
    list_view_header* (*add_header)(struct lw *this, char *text, bool expanded, uint32_t data);

    /* Adds a header as a sub element to another header */
    list_view_header* (*add_sub_header)(struct lw *this, list_view_header *header, bool expanded,
                                      uint32_t data, char *txt, ...) PRINTF_FORMAT(5, 6);

    /* Adds a text element to the list view. */
    list_view_item* (*add_text_element)(struct lw *this, list_view_header *header, int attr,
                                        char *txt, ...) PRINTF_FORMAT(4, 5);

    /* Sets the header on line 'i' to expanded */
    void (*set_expanded)(struct lw *this, int i, bool expanded);

    /* Returns whether the header on line 'i' is expanded or not */
    bool (*get_expanded)(struct lw *this, int i);

    /* Returns the data stored for the header, if applicable. */
    int32_t (*get_data)(struct lw *this, int i);

    /* Returns the attribute assciated with the element */
    uint32_t (*get_attribute)(struct lw *this, int i);

    /* Prints the elements of the list view in the window 'win' */
    void (*render)(struct lw *this, WINDOW *win);
} list_view;

list_view *create_list_view(void);
void free_list_view(list_view *lw);

#endif
