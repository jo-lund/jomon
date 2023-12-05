#include <string.h>
#include "ui.h"
#include "../jomon.h"

#define NCOMPONENTS 2

static struct ui *uis[NCOMPONENTS];
static unsigned int uidx = 0;
static struct ui *active = NULL;
static bool initialized = false;

void ui_register(struct ui *ui, bool is_default)
{
    if (uidx >= NCOMPONENTS) {
        DEBUG("Error registering ui: %s", ui->name);
        return;
    }
    uis[uidx++] = ui;
    if (is_default)
        active = ui;
}

void ui_init(void)
{
    if (active) {
        if (!initialized && active->init)
            active->init();
        initialized = true;
    }
}

void ui_fini(void)
{
    if (active) {
        if (initialized && active->fini)
            active->fini();
        initialized = false;
    }
}

void ui_draw(void)
{
    if (initialized && active && active->draw)
        active->draw();
}

void ui_event(int event)
{
    if (initialized && active && active->event)
        active->event(event);
}

void ui_set_active(const char *name)
{
    for (int i = 0; i < NCOMPONENTS; i++) {
        if (uis[i] && strcmp(name, uis[i]->name) == 0) {
            active = uis[i];
            break;
        }
    }
}
