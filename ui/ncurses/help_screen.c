#include "help_screen.h"
#include "screen.h"
#include "monitor.h"
#include "actionbar.h"

static void help_screen_got_focus(screen *s UNUSED, screen *old UNUSED)
{
    actionbar->visible = false;
}

static void help_screen_lost_focus(screen *s UNUSED, screen *old UNUSED)
{
    actionbar->visible = true;
}

static void help_screen_get_input(screen *s)
{
    wgetch(s->win); /* remove character from input queue */
    pop_screen();
}

static void help_screen_render(void)
{
    int y, x;
    WINDOW *win = screen_cache_get(HELP_SCREEN)->win;
    int hdrcol = get_theme_colour(HEADER_TXT);
    int subcol = get_theme_colour(HELP_TXT);

    x = 0;
    y = 0;
    werase(win);
    wbkgd(win, get_theme_colour(BACKGROUND));
    wprintw(win, "Monitor (c) 2014 - 2022 John Olav Lund");
    y += 2;
    mvwprintw(win, y, x, "When a packet scan is active you can enter interactive mode "
              "by pressing \'i\'. In interactive mode the packet scan will continue in the "
              "background.");
    y += 2;
    printat(win, y, x, hdrcol, "General keyboard shortcuts");
    printat(win, ++y, x, subcol, "%12s", "s");
    wprintw(win, ": Show statistics");
    printat(win, ++y, x, subcol, "%12s", "c");
    wprintw(win, ": Show TCP connections");
    printat(win, ++y, x, subcol, "%12s", "h");
    wprintw(win, ": Show hosts");
    printat(win, ++y, x, subcol, "%12s", "i");
    wprintw(win, ": Enter interactive mode (main screen and connection list)");
    printat(win, ++y, x, subcol, "%12s", "n");
    wprintw(win, ": Change between numerical or resolved addresses");
    printat(win, ++y, x, subcol, "%12s", "p/P");
    wprintw(win, ": Switch to next/previous page (where applicable)");
    printat(win, ++y, x, subcol, "%12s", "F1");
    wprintw(win, ": Show help");
    printat(win, ++y, x, subcol, "%12s", "F2");
    wprintw(win, ": Show menu");
    printat(win, ++y, x, subcol, "%12s", "Esc x F3");
    wprintw(win, ": Go back");
    printat(win, ++y, x, subcol, "%12s", "F10 q");
    wprintw(win, ": Quit");
    y += 2;
    printat(win, y, x, hdrcol, "Main screen keyboard shortcuts");
    printat(win, ++y, x, subcol, "%12s", "F3");
    wprintw(win, ": Start packet scan");
    printat(win, ++y, x, subcol, "%12s", "F4");
    wprintw(win, ": Stop packet scan");
    printat(win, ++y, x, subcol, "%12s", "F5");
    wprintw(win, ": Save file in pcap format (or ascii and raw format for TCP stream)");
    printat(win, ++y, x, subcol, "%12s", "F6");
    wprintw(win, ": Load file in pcap format");
    printat(win, ++y, x, subcol, "%12s", "F7");
    wprintw(win, ": Change between decoded view or hexdump");
    printat(win, ++y, x, subcol, "%12s", "F8 e");
    wprintw(win, ": Add a display filter (tcpdump syntax)");
    y += 2;
    printat(win, y, x, hdrcol, "Connection screen keyboard shortcuts");
    printat(win, ++y, x, subcol, "%12s", "f");
    wprintw(win, ": Show/remove/grey out closed connections");
    printat(win, ++y, x, subcol, "%12s", "p");
    wprintw(win, ": Switch between connection and process view (for live captures)");
    x = 85;
    y = 4;
    printat(win, y, x, hdrcol, "Keyboard shortcuts in interactive mode");
    printat(win, ++y, x, subcol, "%12s", "Arrows");
    wprintw(win, ": Scroll the packet list");
    printat(win, ++y, x, subcol, "%12s", "Space pgdown");
    wprintw(win, ": Scroll page down");
    printat(win, ++y, x, subcol, "%12s", "b pgup");
    wprintw(win, ": Scroll page up");
    printat(win, ++y, x, subcol, "%12s", "Home End");
    wprintw(win, ": Go to first/last page");
    printat(win, ++y, x, subcol, "%12s", "f");
    wprintw(win, ": Follow TCP stream");
    printat(win, ++y, x, subcol, "%12s", "g");
    wprintw(win, ": Go to line");
    printat(win, ++y, x, subcol, "%12s", "m");
    wprintw(win, ": Change hexdump mode");
    printat(win, ++y, x, subcol, "%12s", "Enter");
    wprintw(win, ": Inspect packet");
    printat(win, ++y, x, subcol, "%12s", "Esc");
    wprintw(win, ": Close packet window/Quit interactive mode");
    printat(win, ++y, x, subcol, "%12s", "i");
    wprintw(win, ": Quit interactive mode");
    y += 2;
    printat(win, y, x, hdrcol, "Statistics screen keyboard shortcuts");
    printat(win, ++y, x, subcol, "%12s", "e");
    wprintw(win, ": Switch between bytes and output in human readable format");
    printat(win, ++y, x, subcol, "%12s", "E");
    wprintw(win, ": Change network data rate unit");
    printat(win, ++y, x, subcol, "%12s", "p");
    wprintw(win, ": Show network or CPU & memory statistics");
    printat(win, ++y, x, subcol, "%12s", "v");
    wprintw(win, ": Show/hide packet statistics");
}

static void help_screen_refresh(screen *s)
{
    help_screen_render();
    touchwin(s->win);
    wrefresh(s->win);
}

screen *help_screen_create(void)
{
    screen *s;
    static screen_operations op;
    int my, mx;

    op = SCREEN_OPS(.screen_get_input = help_screen_get_input,
                    .screen_refresh = help_screen_refresh,
                    .screen_got_focus = help_screen_got_focus,
                    .screen_lost_focus = help_screen_lost_focus);
    s = screen_create(&op);
    getmaxyx(stdscr, my, mx);
    s->win = newwin(my, mx, 0, 0);
    keypad(s->win, TRUE);
    return s;
}
