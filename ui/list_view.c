#include <string.h>
#include <stdlib.h>
#include "list_view.h"
#include "../misc.h"

enum type {
    HEADER,
    TEXT
};

static list_view_item *add_header(list_view *this, char *text, bool expanded, uint32_t data);
static list_view_item *add_sub_header(list_view *this, list_view_item *header, bool expanded,
                                      uint32_t data, char *text, ...);
static list_view_item *add_text_element(list_view *this, list_view_item *header, char *txt, ...);
static void free_list_view_item(list_t *widgets);
static void render(list_view *this, WINDOW *win);
static bool get_expanded(list_view *this, int i);
static void set_expanded(list_view *this, int i, bool expanded);
static int32_t get_data(list_view *this, int i);
static uint32_t get_attribute(list_view *this, int i);
static void print_widgets(list_t *widgets, WINDOW *win, int pad, int *line);
static list_view_item *create_element(enum type t, char *text, bool expanded, uint16_t data, uint32_t attr);
static list_view_item *get_widget(list_t *widgets, int i, int *j);
static int get_size(list_t *widgets);

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
        free_list_view_item(lw->widgets);
        free(lw);
    }
}

void free_list_view_item(list_t *widgets)
{
    const node_t *n = list_begin(widgets);

    while (n) {
        list_view_item *w = (list_view_item *) list_data(n);

        if (w->type == HEADER && w->hdr.subwidgets) {
            free_list_view_item(w->hdr.subwidgets);
        }
        free(w->txt);
        n = list_next(n);
    }
    list_free(widgets);
}

list_view_item *create_element(enum type t, char *txt, bool expanded, uint16_t data, uint32_t attr)
{
    char *elem;
    int len;
    list_view_item *widget;

    widget = malloc(sizeof(list_view_item));
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
        widget->hdr.expanded = expanded;
        widget->hdr.data = data;
        widget->hdr.subwidgets = NULL;
        widget->attr = attr;
    } else {
        elem = malloc(len + 1);
        strncpy(elem, txt, len + 1);
        widget->attr = A_NORMAL;
    }
    widget->txt = elem;
    return widget;
}

list_view_item *add_header(list_view *this, char *txt, bool expanded, uint32_t data)
{
    list_view_item *w = create_element(HEADER, txt, expanded, data, A_BOLD);

    list_push_back(this->widgets, w);
    this->num_elements++;
    this->size++;
    return w;
}

list_view_item *add_text_element(list_view *this, list_view_item *header, char *txt, ...)
{
    if (header->type != HEADER) return NULL;

    va_list ap;
    char buf[MAXLINE];
    list_view_item *w;

    va_start(ap, txt);
    vsnprintf(buf, MAXLINE - 1, txt, ap);
    strcat(buf, "\n");
    va_end(ap);
    w = create_element(TEXT, buf, false, 0, A_NORMAL);
    if (!header->hdr.subwidgets) {
        header->hdr.subwidgets = list_init(NULL);
    }
    list_push_back(header->hdr.subwidgets, w);
    this->num_elements++;
    if (header->hdr.expanded) {
        this->size++;
    }
    return w;
}

list_view_item *add_sub_header(list_view *this, list_view_item *header, bool expanded,
                               uint32_t data, char *txt, ...)
{
    va_list ap;
    char buf[MAXLINE];
    list_view_item *h;

    va_start(ap, txt);
    vsnprintf(buf, MAXLINE - 1, txt, ap);
    strcat(buf, "\n");
    va_end(ap);
    h = create_element(HEADER, buf, expanded, data, A_BOLD);
    if (!header->hdr.subwidgets) {
        header->hdr.subwidgets = list_init(NULL);
    }
    list_push_back(header->hdr.subwidgets, h);
    this->num_elements++;
    if (header->hdr.expanded) {
        this->size++;
    }
    return h;
}

void render(list_view *this, WINDOW *win)
{
    int line = 0;
    print_widgets(this->widgets, win, 2, &line);
}

void print_widgets(list_t *widgets, WINDOW *win, int pad, int *line)
{
    const node_t *n = list_begin(widgets);

    while (n) {
        list_view_item *w = list_data(n);
        
        if (w->type == HEADER) {
            mvwprintw(win, *line, pad, "%s", w->txt);
            mvwchgat(win, *line, 0, -1, w->attr, 0, NULL);
            (*line)++;
            if (w->hdr.expanded && w->hdr.subwidgets) {
                print_widgets(w->hdr.subwidgets, win, pad + 2, line);
            }
        } else {
            mvwprintw(win, *line, pad, "%s", w->txt);
            (*line)++;
        }
        n = list_next(n);
    }
}

bool get_expanded(list_view *this, int i)
{
    int j = 0;
    list_view_item *w;

    w = get_widget(this->widgets, i, &j);
    if (w && w->type == HEADER) {
        return w->hdr.expanded;
    }
    return false;
}

void set_expanded(list_view *this, int i, bool expanded)
{
    int j = 0;
    list_view_item *w;

    w = get_widget(this->widgets, i, &j);
    if (w && w->type == HEADER) {
        w->hdr.expanded = expanded;
        if (expanded && w->hdr.subwidgets) {
            this->size += get_size(w->hdr.subwidgets);
            *w->txt = '-';
        } else if (w->hdr.subwidgets) {
            this->size -= get_size(w->hdr.subwidgets);
            *w->txt = '+';
        }
    }
}

int32_t get_data(list_view *this, int i)
{
    int j = 0;
    list_view_item *w;

    w = get_widget(this->widgets, i, &j);
    if (w && w->type == HEADER) {
        return w->hdr.data;
    }
    return -1;
}

uint32_t get_attribute(list_view *this, int i)
{
    int j = 0;
    list_view_item *w;
    
    w = get_widget(this->widgets, i, &j);
    if (w) {
        return w->attr;
    }
    return 0;
}

list_view_item *get_widget(list_t *widgets, int i, int *j)
{
    if (i < 0) return NULL;

    const node_t *n = list_begin(widgets);

    while (n) {
        list_view_item *w = list_data(n);

        if (i == *j && w) return w;
        if (++*j > i) return NULL;
        if (w->type == HEADER && w->hdr.subwidgets && w->hdr.expanded) {
            list_view_item *widget = get_widget(w->hdr.subwidgets, i, j);

            if (widget) return widget;
        }
        n = list_next(n);
    }
    return NULL;
}

int get_size(list_t *widgets)
{
    int size = list_size(widgets);
    const node_t *n = list_begin(widgets);

    while (n) {
        list_view_item *w = list_data(n);

        if (w->type == HEADER && w->hdr.expanded && w->hdr.subwidgets) {
            size += get_size(w->hdr.subwidgets);
        }
        n = list_next(n);
    }
    return size;
}
