#ifndef LIST_VIEW_H
#define LIST_VIEW_H

#include <stdbool.h>
#include <stdint.h>
#include <ncurses.h>
#include "../list.h"

#define ADD_HEADER(o, text, expanded, data) (o)->add_header(o, text, expanded, data)
#define ADD_SUB_HEADER(o, w, text, expanded, data) (o)->add_sub_header(o, w, text, expanded, data)
#define ADD_TEXT_ELEMENT(o, x, text, ...) (o)->add_text_element(o, x, text, ## __VA_ARGS__)
#define ADD_SUB_ELEMENT(o, w, text, ...) (o)->add_sub_element(o, w, text, ## __VA_ARGS__)
#define SET_EXPANDED(o, i, expanded) (o)->set_expanded(o, i, expanded)
#define GET_EXPANDED(o, i) (o)->get_expanded(o, i)
#define GET_DATA(o, i) (o)->get_data(o, i)
#define GET_ATTR(o, i) (o)->get_attribute(o, i)
#define RENDER(o, win) (o)->render(o, win)

typedef struct {
    bool expanded;
    int32_t data;
} header;

typedef struct {
    int i; /* line number */
    char *txt;
    uint32_t attr;
    uint16_t type;
    list_t *subwidgets;

    union {
        header hdr;
        int x; /* indentation relative to the header. */
    };
} list_view_widget;

typedef struct lw {
    int num_elements;
    list_t *widgets;

    /*
     * Adds a header element to the list view. The header will be prefixed by '+'
     * or '-' depending on whether it is expanded or not.
     */
    list_view_widget* (*add_header)(struct lw *this, char *text, bool expanded, uint32_t data);

    /* Adds a header as a sub element to another header */
    list_view_widget* (*add_sub_header)(struct lw *this, list_view_widget *widget, char *text,
                                        bool expanded, uint32_t data);

    list_view_widget* (*add_sub_element)(struct lw *this, list_view_widget *widget, char *txt, ...);

    /*
     * Adds a text element to the list view. 'x' is the amount of extra indentation.
     * Normal, for x = 0, is 2 spaces indentation relative to the header
     */
    list_view_widget* (*add_text_element)(struct lw *this, int x, char *txt, ...);

    /* Sets the header on line 'i' to expanded */
    void (*set_expanded)(struct lw *this, int i, bool expanded);

    /* Returns whether the header on line 'i' is expanded or not */
    bool (*get_expanded)(struct lw *this, int i);

    /* Returns the data stored for the header, if applicable. */
    int32_t (*get_data)(struct lw *this, int i);

    uint32_t (*get_attribute)(struct lw *this, int i);

    /* Prints the elements of the list view in the window 'win' */
    void (*render)(struct lw *this, WINDOW *win);
} list_view;

list_view *create_list_view();
void free_list_view(list_view *lw);

#endif
