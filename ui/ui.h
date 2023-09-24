#ifndef UI_H
#define UI_H

#include <stdbool.h>

struct ui {
    char *name;
    void (*init)(void);
    void (*fini)(void);
    void (*draw)(void);
    void (*event)(int);
};

enum ui_event {
    UI_NEW_DATA,
    UI_RESIZE,
    UI_INPUT,
    UI_ALARM
};

void ui_register(struct ui *ui, bool is_default);
void ui_init(void);
void ui_fini(void);
void ui_draw(void);
void ui_event(int ev);
void ui_set_active(const char *name);

#endif
