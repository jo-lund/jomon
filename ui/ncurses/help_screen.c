#include "help_screen.h"
#include "screen.h"
#include "jomon.h"
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
    wprintw(win, "Jomon (c) 2014 - 2024 John Olav Lund");
    y += 2;
    mvwprintw(win, y, x, "When a packet scan is active you can enter interactive mode "
              "by pressing ");
    printat(win, A_BOLD, "i");
    wprintw(win, ". In interactive mode the packet scan will continue in the background");
    y += 2;
    mvprintat(win, y, x, hdrcol, "General keyboard shortcuts");
    mvprintat(win, ++y, x, subcol, "%12s", "s");
    wprintw(win, ": Show statistics");
    mvprintat(win, ++y, x, subcol, "%12s", "c");
    wprintw(win, ": Show TCP connections");
    mvprintat(win, ++y, x, subcol, "%12s", "h");
    wprintw(win, ": Show hosts");
    mvprintat(win, ++y, x, subcol, "%12s", "i");
    wprintw(win, ": Enter interactive mode (main screen and connection list)");
    mvprintat(win, ++y, x, subcol, "%12s", "n");
    wprintw(win, ": Change between numerical or resolved addresses");
    mvprintat(win, ++y, x, subcol, "%12s", "N");
    wprintw(win, ": Change between FQDN and host name");
    mvprintat(win, ++y, x, subcol, "%12s", "p/P");
    wprintw(win, ": Switch to next/previous page (where applicable)");
    mvprintat(win, ++y, x, subcol, "%12s", "Tab");
    wprintw(win, ": Select header and use ");
    printat(win, A_BOLD, "Enter ");
    wprintw(win, "to sort and ");
    printat(win, A_BOLD, "Esc ");
    wprintw(win, "to exit selection");
    mvprintat(win, ++y, x, subcol, "%12s", "? F1");
    wprintw(win, ": Show help");
    mvprintat(win, ++y, x, subcol, "%12s", "F2");
    wprintw(win, ": Show menu");
    mvprintat(win, ++y, x, subcol, "%12s", "Esc x F3");
    wprintw(win, ": Go back");
    mvprintat(win, ++y, x, subcol, "%12s", "F10 q");
    wprintw(win, ": Quit");
    y += 2;
    mvprintat(win, y, x, hdrcol, "Main screen keyboard shortcuts");
    mvprintat(win, ++y, x, subcol, "%12s", "F3");
    wprintw(win, ": Start packet scan");
    mvprintat(win, ++y, x, subcol, "%12s", "F4");
    wprintw(win, ": Stop packet scan");
    mvprintat(win, ++y, x, subcol, "%12s", "F5");
    wprintw(win, ": Save file in pcap format (or ascii and raw format for TCP stream)");
    mvprintat(win, ++y, x, subcol, "%12s", "F6");
    wprintw(win, ": Export marked packets in pcap format");
    mvprintat(win, ++y, x, subcol, "%12s", "F7");
    wprintw(win, ": Load file in pcap format");
    mvprintat(win, ++y, x, subcol, "%12s", "F8");
    wprintw(win, ": Change between decoded view or hexdump");
    mvprintat(win, ++y, x, subcol, "%12s", "F9 e");
    wprintw(win, ": Add a display filter (tcpdump syntax)");
    y += 2;
    mvprintat(win, y, x, hdrcol, "Connection screen keyboard shortcuts");
    mvprintat(win, ++y, x, subcol, "%12s", "f");
    wprintw(win, ": Show/remove/grey out closed connections");
    mvprintat(win, ++y, x, subcol, "%12s", "p");
    wprintw(win, ": Switch between connection and process view (for live captures)");
    x = 85;
    y = 4;
    mvprintat(win, y, x, hdrcol, "Keyboard shortcuts in interactive mode");
    mvprintat(win, ++y, x, subcol, "%12s", "Arrows");
    wprintw(win, ": Scroll the packet list");
    mvprintat(win, ++y, x, subcol, "%12s", "Ctrl+down");
    wprintw(win, ": Go to next selectable item");
    mvprintat(win, ++y, x, subcol, "%12s", "Ctrl+up");
    wprintw(win, ": Go to previous selectable item");
    mvprintat(win, ++y, x, subcol, "%12s", "Space pgdown");
    wprintw(win, ": Scroll page down");
    mvprintat(win, ++y, x, subcol, "%12s", "b pgup");
    wprintw(win, ": Scroll page up");
    mvprintat(win, ++y, x, subcol, "%12s", "Home End");
    wprintw(win, ": Go to first/last page");
    mvprintat(win, ++y, x, subcol, "%12s", "f");
    wprintw(win, ": Follow TCP stream");
    mvprintat(win, ++y, x, subcol, "%12s", "g");
    wprintw(win, ": Go to line");
    mvprintat(win, ++y, x, subcol, "%12s", "m");
    wprintw(win, ": Change hexdump mode");
    mvprintat(win, ++y, x, subcol, "%12s", "Enter");
    wprintw(win, ": Inspect packet");
    mvprintat(win, ++y, x, subcol, "%12s", "Esc");
    wprintw(win, ": Close packet window/Quit interactive mode");
    mvprintat(win, ++y, x, subcol, "%12s", "i");
    wprintw(win, ": Quit interactive mode");
    mvprintat(win, ++y, x, subcol, "%12s", "M");
    wprintw(win, ": Mark/unmark packet");
    y += 2;
    mvprintat(win, y, x, hdrcol, "Statistics screen keyboard shortcuts");
    mvprintat(win, ++y, x, subcol, "%12s", "e");
    wprintw(win, ": Switch between bytes and output in human readable format");
    mvprintat(win, ++y, x, subcol, "%12s", "E");
    wprintw(win, ": Change network data rate unit");
    mvprintat(win, ++y, x, subcol, "%12s", "p");
    wprintw(win, ": Show network or CPU & memory statistics");
    mvprintat(win, ++y, x, subcol, "%12s", "v");
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
