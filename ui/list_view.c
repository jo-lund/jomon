#include <string.h>
#include <stdlib.h>
#include "list_view.h"
#include "../misc.h"

enum type {
    HEADER,
    TEXT
};

static list_view_widget *add_header(list_view *this, char *text, bool expanded, uint32_t data);
static void add_sub_header(list_view *this, list_view_widget *widget, char *text, bool expanded);
static list_view_widget *add_text_element(list_view *this, int x, char *txt, ...);
static list_view_widget *create_element(enum type t, char *text, bool expanded, int x, int line, uint16_t data);
static void free_list_view_widget(list_t *widgets);
static void render(list_view *this, WINDOW *win);
static void print_widgets(list_t *widgets, WINDOW *win, int pad);
static bool get_expanded(list_view *this, int i);
static void set_expanded(list_view *this, int i, bool expanded);
static int32_t get_data(list_view *this, int i);
static uint32_t get_attribute(list_view *this, int i);

list_view *create_list_view()
{
    list_view *widget = malloc(sizeof(list_view));

    widget->add_header = add_header;
    widget->add_sub_header = add_sub_header;
    widget->add_text_element = add_text_element;
    widget->render = render;
    widget->set_expanded = set_expanded;
    widget->get_expanded = get_expanded;
    widget->get_data = get_data;
    widget->get_attribute = get_attribute;
    widget->widgets = list_init(NULL);
    widget->num_elements = 0;
    return widget;
}

void free_list_view(list_view *lw)
{
    if (lw) {
        free_list_view_widget(lw->widgets);
        free(lw);
    }
}

void free_list_view_widget(list_t *widgets)
{
    const node_t *n = list_begin(widgets);

    while (n) {
        list_view_widget *w = (list_view_widget *) list_data(n);

        if (w->type == HEADER && w->hdr.subwidgets) {
            free_list_view_widget(w->hdr.subwidgets);
        }
        free(w->txt);
        n = list_next(n);
    }
    list_free(widgets);
}

list_view_widget *create_element(enum type t, char *txt, bool expanded, int x, int line, uint16_t data)
{
    char *elem;
    int len;
    list_view_widget *widget;

    widget = malloc(sizeof(list_view_widget));
    widget->type = t;
    len = strlen(txt);
    if (t == HEADER) {
        elem = malloc(len + 3);
        if (expanded) {
            strncpy(elem, "- ", 2); 
        } else {
            strncpy(elem, "+ ", 2);
        }
        strncpy(elem + 2, txt, len + 1);
        widget->hdr.subwidgets = NULL;
        widget->hdr.expanded = expanded;
        widget->hdr.data = data;
        widget->attr = A_BOLD; // TODO: Should be configurable
    } else {
        elem = malloc(len + 1);
        strncpy(elem, txt, len + 1);
        widget->x = x;
        widget->attr = A_NORMAL;
    }
    widget->txt = elem;
    widget->i = line;

    return widget;
}

list_view_widget *add_header(list_view *this, char *txt, bool expanded, uint32_t data)
{
    list_view_widget *w = create_element(HEADER, txt, expanded, -1, this->num_elements, data);

    list_push_back(this->widgets, w);
    this->num_elements++;
    return w;
}

list_view_widget *add_text_element(list_view *this, int x, char *txt, ...)
{
    va_list ap;
    char buf[MAXLINE];
    list_view_widget *w;

    va_start(ap, txt);
    vsnprintf(buf, MAXLINE - 1, txt, ap);
    strcat(buf, "\n");
    va_end(ap);
    w = create_element(TEXT, buf, false, x, this->num_elements, 0);
    list_push_back(this->widgets, w);
    this->num_elements++;
    return w;
}

void add_sub_header(list_view *this, list_view_widget *widget, char *txt, bool expanded)
{
    list_view_widget *w = create_element(HEADER, txt, expanded, -1, widget->i + 1, 0);

    if (!widget->hdr.subwidgets) {
        widget->hdr.subwidgets = list_init(NULL);
    }
    list_push_back(widget->hdr.subwidgets, w);
}

void render(list_view *this, WINDOW *win)
{
    int pad = 2;

    print_widgets(this->widgets, win, pad);
}

void print_widgets(list_t *widgets, WINDOW *win, int pad)
{
    const node_t *n = list_begin(widgets);

    while (n) {
        list_view_widget *w = list_data(n);
        
        if (w->type == HEADER) {
            mvwprintw(win, w->i, pad, w->txt);
            mvwchgat(win, w->i, 0, -1, w->attr, 0, NULL);
            if (w->hdr.subwidgets) {
                print_widgets(w->hdr.subwidgets, win, pad + 2);
            }
        } else {
            mvwprintw(win, w->i, w->x + pad + 2, w->txt);
        }
        n = list_next(n);
    }
}

bool get_expanded(list_view *this, int i)
{
    const node_t *n = list_ith(this->widgets, i);
    list_view_widget *w = list_data(n);
    
    if (w && w->type == HEADER) {
        return w->hdr.expanded;
    }
    return false;
}

static void set_expanded(list_view *this, int i, bool expanded)
{
    const node_t *n = list_ith(this->widgets, i);
    list_view_widget *w = list_data(n);

    if (w && w->type == HEADER) {
        w->hdr.expanded = expanded;
    }
}

int32_t get_data(list_view *this, int i)
{
    const node_t *n = list_ith(this->widgets, i);
    list_view_widget *w = list_data(n);
    
    if (w && w->type == HEADER) {
        return w->hdr.data;
    }
    return -1;
}

uint32_t get_attribute(list_view *this, int i)
{
    const node_t *n = list_ith(this->widgets, i);
    list_view_widget *w = list_data(n);
    
    if (w) {
        return w->attr;
    }
    return 0;
}