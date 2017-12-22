#include "help_screen.h"

static void help_screen_get_input(screen *s);

screen *help_screen_create()
{
    screen *s;
    static screen_operations op;

    op = SCREEN_OPTS(.screen_get_input = help_screen_get_input);
    s = screen_create(&op);
    return s;
}

void help_screen_get_input(screen *s)
{
    pop_screen(s);
}

void help_screen_render()
{
    int y = 0;
    WINDOW *win = screen_cache_get(HELP_SCREEN)->win;
    int hdrcol = get_theme_colour(HEADER_TXT);
    int subcol = get_theme_colour(SUBHEADER_TXT);

    wprintw(win, "Monitor 0.0.1 (c) 2017 John Olav Lund");
    mvwprintw(win, ++y, 0, "");
    mvwprintw(win, ++y, 0, "When a packet scan is active you can enter interactive mode " \
              "by pressing \'i\'. In interactive mode the packet scan will continue in the " \
              "background.");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, hdrcol, "General keyboard shortcuts");
    printat(win, ++y, 0, subcol, "%12s", "F1");
    wprintw(win, ": Show help");
    printat(win, ++y, 0, subcol, "%12s", "F10 q");
    wprintw(win, ": Quit");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, hdrcol, "Main screen keyboard shortcuts");
    printat(win, ++y, 0, subcol, "%12s", "i");
    wprintw(win, ": Enter interactive mode");
    printat(win, ++y, 0, subcol, "%12s", "s");
    wprintw(win, ": Show statistics screen");
    printat(win, ++y, 0, subcol, "%12s", "F2");
    wprintw(win, ": Show menu");
    printat(win, ++y, 0, subcol, "%12s", "F3");
    wprintw(win, ": Start packet scan");
    printat(win, ++y, 0, subcol, "%12s", "F4");
    wprintw(win, ": Stop packet scan");
    printat(win, ++y, 0, subcol, "%12s", "F5");
    wprintw(win, ": Save file in pcap format");
    printat(win, ++y, 0, subcol, "%12s", "F6");
    wprintw(win, ": Load file in pcap format");
    printat(win, ++y, 0, subcol, "%12s", "F7");
    wprintw(win, ": Change between decoded view or hexdump");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, hdrcol, "Keyboard shortcuts in interactive mode");
    printat(win, ++y, 0, subcol, "%12s", "Arrows");
    wprintw(win, ": Scroll the packet list");
    printat(win, ++y, 0, subcol, "%12s", "Space pgdown");
    wprintw(win, ": Scroll page down");
    printat(win, ++y, 0, subcol, "%12s", "b pgup");
    wprintw(win, ": Scroll page up");
    printat(win, ++y, 0, subcol, "%12s", "Home End");
    wprintw(win, ": Go to first/last page");
    printat(win, ++y, 0, subcol, "%12s", "g");
    wprintw(win, ": Go to line");
    printat(win, ++y, 0, subcol, "%12s", "h");
    wprintw(win, ": Change hexdump mode");
    printat(win, ++y, 0, subcol, "%12s", "Enter");
    wprintw(win, ": Inspect packet");
    printat(win, ++y, 0, subcol, "%12s", "Esc");
    wprintw(win, ": Close packet window/Quit interactive mode");
    printat(win, ++y, 0, subcol, "%12s", "i");
    wprintw(win, ": Quit interactive mode");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, hdrcol, "Statistics screen keyboard shortcuts");
    printat(win, ++y, 0, subcol, "%12s", "p");
    wprintw(win, ": Show/hide packet statistics");
    printat(win, ++y, 0, subcol, "%12s", "Esc x");
    wprintw(win, ": Exit statistics screen");
}
