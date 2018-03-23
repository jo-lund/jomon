#include <string.h>
#include <stdlib.h>
#include "list_view.h"
#include "../misc.h"

enum type {
    HEADER,
    TEXT
};

static list_view_header *add_header(list_view *this, char *text, bool expanded, uint32_t data);
static list_view_header *add_sub_header(list_view *this, list_view_header *header, bool expanded,
                                      uint32_t data, char *text, ...);
static list_view_item *add_text_element(list_view *this, list_view_header *header, char *txt, ...);
static void add_separator(list_view *this, list_view_header *hdr);
static void free_list_view_item(list_t *widgets);
static void render(list_view *this, WINDOW *win, int scrollx);
static bool get_expanded(list_view *this, int i);
static void set_expanded(list_view *this, int i, bool expanded);
static int32_t get_data(list_view *this, int i);
static uint32_t get_attribute(list_view *this, int i);
static void print_elements(list_t *widgets, WINDOW *win, int pad, int *line, int scrollx);
static list_view_item *create_item(char *txt, uint32_t attr, uint16_t type);
static list_view_header *create_header(char *txt, bool expanded, uint16_t data, uint32_t attr);
static void list_view_item_init(list_view_item *item, char *txt, uint32_t attr, uint16_t type);
static list_view_item *get_widget(list_t *widgets, int i, int *j);
static int get_size(list_t *widgets);
static bool header_expanded(list_view_header *header);
static list_view_header *get_prev_subheader(list_t *subwidgets);

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
    widget->size = 0;

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

        if (w->type == HEADER && ((list_view_header *) w)->subwidgets) {
            free_list_view_item(((list_view_header *) w)->subwidgets);
        }
        free(w->txt);
        n = list_next(n);
    }
    list_free(widgets, free);
}

list_view_item *create_item(char *txt, uint32_t attr, uint16_t type)
{
    char *elem;
    int len;
    list_view_item *widget;

    widget = malloc(sizeof(list_view_item));
    len = strlen(txt);
    elem = malloc(len + 1);
    strncpy(elem, txt, len + 1);
    list_view_item_init(widget, elem, attr, type);
    return widget;
}

void list_view_item_init(list_view_item *item, char *txt, uint32_t attr, uint16_t type)
{
    item->type = type;
    item->attr = attr;
    item->txt = txt;
}

list_view_header *create_header(char *txt, bool expanded, uint16_t data, uint32_t attr)
{
    char *elem;
    int len;
    list_view_header *widget;

    widget = malloc(sizeof(list_view_header));
    len = strlen(txt);
    elem = malloc(len + 3);
    if (expanded) {
        strncpy(elem, "- ", 2);
    } else {
        strncpy(elem, "+ ", 2);
    }
    strncpy(elem + 2, txt, len + 1);
    list_view_item_init((list_view_item *) widget, elem, attr, HEADER);
    widget->expanded = expanded;
    widget->data = data;
    widget->subwidgets = NULL;
    return widget;
}

list_view_header *add_header(list_view *this, char *txt, bool expanded, uint32_t data)
{
    list_view_header *w = create_header(txt, expanded, data, A_BOLD);
    const node_t *n = list_end(this->widgets);

    if (n) {
        list_view_header *h;

        h = list_data(n);
        add_separator(this, h);
    }
    w->parent = NULL;
    list_push_back(this->widgets, w);
    this->num_elements++;
    this->size++;
    return w;
}

list_view_item *add_text_element(list_view *this, list_view_header *header, char *txt, ...)
{
    va_list ap;
    char buf[MAXLINE];
    list_view_item *w;

    va_start(ap, txt);
    vsnprintf(buf, MAXLINE - 1, txt, ap);
    strcat(buf, "\n");
    va_end(ap);
    w = create_item(buf, A_NORMAL, TEXT);
    if (!header->subwidgets) {
        header->subwidgets = list_init(NULL);
    } else {
        list_view_header *p;

        if ((p = get_prev_subheader(header->subwidgets))) {
            add_separator(this, p);
        }
    }
    list_push_back(header->subwidgets, w);
    this->num_elements++;
    if (header_expanded(header)) {
        this->size++;
    }
    return w;
}

list_view_header *add_sub_header(list_view *this, list_view_header *header, bool expanded,
                                 uint32_t data, char *txt, ...)
{
    va_list ap;
    char buf[MAXLINE];
    list_view_header *h;

    va_start(ap, txt);
    vsnprintf(buf, MAXLINE - 1, txt, ap);
    strcat(buf, "\n");
    va_end(ap);
    h = create_header(buf, expanded, data, A_BOLD);
    h->parent = header;
    if (!header->subwidgets) {
        header->subwidgets = list_init(NULL);
    } else {
        list_view_header *p;

        if ((p = get_prev_subheader(header->subwidgets))) {
            add_separator(this, p);
        }
    }
    list_push_back(header->subwidgets, h);
    this->num_elements++;
    if (header_expanded(header)) {
        this->size++;
    }
    return h;
}

void add_separator(list_view *this, list_view_header *hdr)
{
    if (hdr->subwidgets) {
        list_view_item *w;

        w = create_item("", A_NORMAL, TEXT);
        list_push_back(hdr->subwidgets, w);
        this->num_elements++;
        if (header_expanded(hdr)) {
            this->size++;
        }
    }
}

void render(list_view *this, WINDOW *win, int scrollx)
{
    int line = 0;

    print_elements(this->widgets, win, 2, &line, scrollx);
}

void print_elements(list_t *widgets, WINDOW *win, int pad, int *line, int scrollx)
{
    const node_t *n = list_begin(widgets);

    while (n) {
        list_view_item *w = list_data(n);

        if (scrollx < strlen(w->txt)) {
            wattron(win, w->attr);
            if (scrollx > pad) {
                mvwprintw(win, *line, 0, "%s", w->txt + scrollx - pad);
            } else {
                mvwprintw(win, *line, pad - scrollx, "%s", w->txt);
            }
            wattroff(win, w->attr);
        }
        (*line)++;
        if (w->type == HEADER && ((list_view_header *) w)->expanded &&
            ((list_view_header *) w)->subwidgets) {
            print_elements(((list_view_header *) w)->subwidgets, win, pad + 2, line, scrollx);
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
        return ((list_view_header *) w)->expanded;
    }
    return false;
}

void set_expanded(list_view *this, int i, bool expanded)
{
    int j = 0;
    list_view_item *w;

    w = get_widget(this->widgets, i, &j);
    if (w && w->type == HEADER) {
        list_view_header *h = (list_view_header *) w;

        h->expanded = expanded;
        if (expanded && h->subwidgets) {
            this->size += get_size(h->subwidgets);
            *w->txt = '-';
        } else if (h->subwidgets) {
            this->size -= get_size(h->subwidgets);
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
        return ((list_view_header *) w)->data;
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
        if (w->type == HEADER && ((list_view_header *) w)->subwidgets &&
            ((list_view_header *) w)->expanded) {
            list_view_item *widget = get_widget(((list_view_header *) w)->subwidgets, i, j);
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

        if (w->type == HEADER && ((list_view_header *) w)->expanded &&
            ((list_view_header *) w)->subwidgets) {
            size += get_size(((list_view_header *) w)->subwidgets);
        }
        n = list_next(n);
    }
    return size;
}

/* Returns whether all parent headers are expanded or not */
bool header_expanded(list_view_header *header)
{
    if (!header) {
        return false;
    }
    if (header->expanded && header->parent) {
        return header_expanded(header->parent);
    }
    return header->expanded;
}

list_view_header *get_prev_subheader(list_t *subwidgets)
{
    const node_t *n = list_end(subwidgets);
    list_view_item *w = (list_view_item *) list_data(n);

    if (w->type == HEADER) {
        return (list_view_header *) w;
    }
    return NULL;
}
