#ifndef MAIN_SCREEN_INT_H
#define MAIN_SCREEN_INT_H

#include "ui/print_protocol.h"

#define NUM_COLS_SCROLL 4

enum views {
    DECODED_VIEW,
    HEXDUMP_VIEW,
    NUM_VIEWS
};

enum input_mode {
    INPUT_NONE,
    INPUT_GOTO,
    INPUT_FILTER
};

extern char load_filepath[MAXPATH];
extern file_dialogue *load_dialogue;
extern file_dialogue *save_dialogue;

// TODO: Move functions that don't need to be static to struct main_screen.
void main_screen_write_show_progress(int size);
void main_screen_save(vector_t *data, const char *file);
void main_screen_save_handle_cancel(void *);
void main_screen_load_handle_ok(void *file);
void main_screen_load_handle_cancel(void *);
void main_screen_refresh(screen *s);
void main_screen_clear(main_screen *ms);
void main_screen_get_input(screen *s);
void main_screen_handle_keydown(main_screen *ms, int num_lines);
void main_screen_handle_keyup(main_screen *ms, int num_lines);
void main_screen_scroll_page(main_screen *ms, int num_lines);
void main_screen_scroll_column(main_screen *ms, int scrollx);
void main_screen_goto_line(main_screen *ms, int c);
void main_screen_goto_end(main_screen *ms);
void main_screen_goto_home(main_screen *ms);
void main_screen_update_window(main_screen *ms, char *buf);

#endif
