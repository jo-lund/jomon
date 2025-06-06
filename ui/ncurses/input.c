#include <ncurses.h>
#include <string.h>
#include <ctype.h>
#include "input.h"
#include "jomon.h"

#define HISTORY_SIZE 128
#define HISTORY_NEXT -1
#define HISTORY_PREV 1

struct input_state {
    char buf[MAXLINE]; /* the current line */
    int pos; /* cursor position */
    int len; /* current length of buffer */
    const char *prompt;
    int plen; /* length of prompt */
    int valid_keys;
    WINDOW *win;
    char **history;
    int history_idx;
    int history_len;
};

static bool valid_key(struct input_state *s, int c)
{
    switch (s->valid_keys) {
    case INPUT_DIGITS:
        if (isdigit(c))
            return true;
        break;
    default:
        if (c >= 0x20 && c < 0x7f)
            return true;
        break;
    }
    return false;
}

static void show_history(struct input_state *s, int dir)
{
    int n;
    const char *p;

    if (s->history_len == 0)
        return;
    if ((dir == HISTORY_PREV && s->history_idx >= s->history_len - 1) ||
        (dir == HISTORY_NEXT && s->history_idx == 0))
        return;
    if (dir == HISTORY_PREV && s->history_idx == 0) {
        free(s->history[s->history_len - 1]);
        s->history[s->history_len - 1] = xstrdup(s->buf);
    }
    s->history_idx += dir;
    p = s->history[s->history_len - 1 - s->history_idx];
    n = strlcpy(s->buf, p, MAXLINE);
    s->pos = n;
    s->len = n;
    input_refresh(s);
}

struct input_state *input_init(WINDOW *win, const char *prompt)
{
    struct input_state *s;

    s = xcalloc(1, sizeof(struct input_state));
    s->win = win;
    s->prompt = prompt;
    s->plen = strlen(prompt);
    s->valid_keys = INPUT_ALL;
    s->history_idx = 0;
    s->history = xcalloc(HISTORY_SIZE, sizeof(char*));
    input_add_history(s, ""); /* add current empty line to history */
    return s;
}

int input_edit(struct input_state *s, int c)
{
    switch (c) {
    case KEY_ENTER:
    case '\n':
        return 1;
    case KEY_BACKSPACE:
    case '\b':
        if (s->pos > 0 && s->len > 0) {
            if (s->pos < s->len)
                memmove(s->buf + s->pos - 1, s->buf + s->pos, s->len - s->pos);
            s->pos--;
            s->len--;
            s->buf[s->len] = '\0';
            input_refresh(s);
        }
        break;
    case KEY_LEFT:
        if (s->pos > 0) {
            s->pos--;
            wmove(s->win, 0, s->plen + s->pos);
            wrefresh(s->win);
        }
        break;
    case KEY_RIGHT:
        if (s->pos < s->len) {
            s->pos++;
            wmove(s->win, 0, s->plen + s->pos);
            wrefresh(s->win);
        }
        break;
    case KEY_DC:
        if (s->len > 0 && s->pos < s->len) {
            memmove(s->buf + s->pos, s->buf + s->pos + 1, s->len - s->pos + 1);
            s->len--;
            s->buf[s->len] = '\0';
            input_refresh(s);
        }
        break;
    case KEY_HOME:
        s->pos = 0;
        wmove(s->win, 0, s->plen + s->pos);
        wrefresh(s->win);
        break;
    case KEY_END:
        s->pos = s->len;
        wmove(s->win, 0, s->plen + s->pos);
        wrefresh(s->win);
        break;
    case KEY_UP:
        show_history(s, HISTORY_PREV);
        break;
    case KEY_DOWN:
        show_history(s, HISTORY_NEXT);
        break;
    default:
        if (s->pos >= MAXLINE - 1 || !valid_key(s, c))
            return -1;
        if (s->pos == s->len) {
            s->buf[s->pos++] = c;
            s->buf[s->pos] = '\0';
            s->len++;
        } else {
            memmove(s->buf + s->pos + 1, s->buf + s->pos, s->len - s->pos);
            s->buf[s->pos++] = c;
            s->buf[++s->len] = '\0';
        }
        input_refresh(s);
        break;
    }
    return 0;
}

void input_add_string(struct input_state *s, char *str)
{
    int n;

    n = strlcpy(s->buf, str, MAXLINE);
    s->pos = n;
    s->len = n;
    input_refresh(s);
}

void input_add_history(struct input_state *s, const char *line)
{
    if (s->history_len > 0) {
        char *tmp;

        if (s->history_len >= HISTORY_SIZE) {
            free(s->history[0]);
            memmove(s->history, s->history + 1, sizeof(char*) * (HISTORY_SIZE - 1));
            s->history_len--;
        }
        tmp = s->history[s->history_len-1];
        s->history[s->history_len-1] = xstrdup(line);
        s->history[s->history_len++] = tmp;
    } else {
        s->history[s->history_len++] = xstrdup(line);
    }
}

void input_set_valid_keys(struct input_state *s, enum valid_keys valid)
{
    s->valid_keys = valid;
}

void input_refresh(struct input_state *s)
{
    wmove(s->win, 0, s->plen);
    wclrtoeol(s->win);
    waddstr(s->win, s->buf);
    wmove(s->win, 0, s->plen + s->pos);
    wrefresh(s->win);
}

void input_exit(struct input_state *s)
{
    s->buf[0] = '\0';
    s->pos = 0;
    s->len = 0;
    s->history_idx = 0;
    curs_set(0);
    werase(s->win);
}

void input_print_prompt(struct input_state *s)
{
    werase(s->win);
    waddstr(s->win, s->prompt);
    curs_set(1);
    wrefresh(s->win);
}

char *input_get_buffer(struct input_state *s)
{
    return s->buf;
}

void input_free(struct input_state *s)
{
    for (int i = 0; i < s->history_len; i++)
        free(s->history[i]);
    free(s->history);
    free(s);
}
