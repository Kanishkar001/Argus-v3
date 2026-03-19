from cmd2 import with_category
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from difflib import get_close_matches

from argus.cli.status_bar import print_status_bar

__mixin_name__ = "HelpMixin"

TEAL = "#2EC4B6"
CAT_COLOR = "magenta"
CMD_COLOR = "white"
LABEL_COLOR = "bold " + TEAL
DIM = "dim"

_ENTRIES = [
    ("Module Browse", "modules [infra|web|sec|tag:<t>] [-d] [-s], search <k>, searchre <re>"),
    ("Select",        "use <id|name>, ?<id>, helpmod <id>"),
    ("Run",           "run [ids...] [target], runall <infra|web|security>, runfav, last"),
    ("Options",       "set target v, set threads n, set opt v, set id opt v, unset opt, opts [id], show options_full"),
    ("Info",          "scope, recent, fav [add|del|run|list|clear|tag:<tag>], viewout [mod], grepout <re>"),
    ("Profiles",      "profile speed|deep|safe"),
    ("Utility",       "clear, banner, info, reset [favorites|recent|options], config, api [service] [key]"),
    ("Other",         "help <command>, exit, quit"),
]

_CMD_DOCS = {
    "modules":  {"usage": "modules [infra|web|sec|tag:<tag>] [-d] [-s]",
                 "desc":  "List modules. Filter by family or tag. -d adds details, -s prints IDs only.",
                 "ex":    ["modules infra -d", "modules tag:cloud", "modules -s"]},
    "search":   {"usage": "search <keyword>",
                 "desc":  "Keyword search over module names and descriptions.",
                 "ex":    ["search ssl", "search takeover"]},
    "searchre": {"usage": "searchre <regex>",
                 "desc":  "Regex search over module names and descriptions.",
                 "ex":    ["searchre '(?i)dns.*brute'"]},
    "use":      {"usage": "use <id|name>",
                 "desc":  "Select a module as context. Subsequent opts/show/run without IDs target this module.",
                 "ex":    ["use 42", "use subdomain_enum_pro"]},
    "?":        {"usage": "?<id>",
                 "desc":  "Quick peek at a module (short info or last output preview).",
                 "ex":    ["?42"]},
    "helpmod":  {"usage": "helpmod <id>",
                 "desc":  "Show the module's own help/README if available.",
                 "ex":    ["helpmod 7"]},
    "run":      {"usage": "run [ids...] [target]",
                 "desc":  "Run one or more modules. If no IDs, runs the current 'use' module. Target overrides global.",
                 "ex":    ["run 5 9 example.com", "run example.com", "run"]},
    "runall":   {"usage": "runall <infra|web|security>",
                 "desc":  "Run all modules in a family.",
                 "ex":    ["runall infra"]},
    "runfav":   {"usage": "runfav",
                 "desc":  "Run every favorite module.",
                 "ex":    ["runfav"]},
    "last":     {"usage": "last",
                 "desc":  "Re-run the last executed command.",
                 "ex":    ["last"]},
    "set":      {"usage": "set <option> <value> | set <id> <option> <value>",
                 "desc":  "Set global or per-module options. Includes validation for target and thread count warnings.",
                 "ex":    ["set target example.com", "set threads 20", "set 5 timeout 30"]},
    "unset":    {"usage": "unset <option>",
                 "desc":  "Unset a global option.",
                 "ex":    ["unset target"]},
    "opts":     {"usage": "opts [id]",
                 "desc":  "Show current effective options. With id: only that module.",
                 "ex":    ["opts", "opts 12"]},
    "show":     {"usage": "show options_full",
                 "desc":  "Dump every option (global + module defaults).",
                 "ex":    ["show options_full"]},
    "scope":    {"usage": "scope",
                 "desc":  "Display current scope: target, threads, filters, etc.",
                 "ex":    ["scope"]},
    "recent":   {"usage": "recent",
                 "desc":  "List recently run modules.",
                 "ex":    ["recent"]},
    "fav":      {"usage": "fav [add|del|run|list|clear|export|import|tag:<tag>]",
                 "desc":  "Manage favorites. add/del modules, run favorites, clear all, export/import lists, add by tag.",
                 "ex":    ["fav add 42", "fav clear", "fav export", "fav import 'dns,ssl,whois'", "fav tag:web"]},
    "viewout":  {"usage": "viewout [module_id|name]",
                 "desc":  "Open saved output for a module.",
                 "ex":    ["viewout 9", "viewout takeover_detector"]},
    "grepout":  {"usage": "grepout <regex> [--case-sensitive] [--count] [--module <name>]",
                 "desc":  "Search through saved outputs using regex. --case-sensitive for exact case, --count for match count only, --module for specific module.",
                 "ex":    ["grepout '(?i)password'", "grepout 'error' --count", "grepout '192.168' --module ssl_chain"]},
    "profile":  {"usage": "profile speed|deep|safe",
                 "desc":  "Switch between preset profiles for threads/timeouts.",
                 "ex":    ["profile speed"]},
    "clear":    {"usage": "clear",
                 "desc":  "Clear the screen.",
                 "ex":    ["clear"]},
    "banner":   {"usage": "banner",
                 "desc":  "Show the banner.",
                 "ex":    ["banner"]},
    "info":     {"usage": "info",
                 "desc":  "Display comprehensive system info including favorites, recent modules, target, and threads.",
                 "ex":    ["info"]},
    "reset":    {"usage": "reset [favorites|recent|options]",
                 "desc":  "Reset state. favorites: clear favorites, recent: clear recent modules, options: clear options, no args: full reset.",
                 "ex":    ["reset", "reset favorites", "reset options", "reset recent"]},
    "help":     {"usage": "help [command]",
                 "desc":  "Show global help or detailed help for a command.",
                 "ex":    ["help run", "help modules"]},
    "config":   {"usage": "config",
                 "desc":  "Open settings.py file in default editor.",
                 "ex":    ["config"]},
    "api":      {"usage": "api [service|id] [key]",
                 "desc":  "Show API status or set API key for a service. Supports service names or IDs.",
                 "ex":    ["api", "api shodan your_key_here", "api 3 your_key_here"]},
    "hm":       {"usage": "hm <id>",
                 "desc":  "Alias for helpmod command.",
                 "ex":    ["hm 42"]},
    "exit":     {"usage": "exit",
                 "desc":  "Quit Argus.",
                 "ex":    ["exit"]},
    "quit":     {"usage": "quit",
                 "desc":  "Quit Argus.",
                 "ex":    ["quit"]},
}

console = Console()


def _panel_title(txt: str) -> Panel:
    return Panel(
        Text(f" {txt} ", justify="center", style=f"bold white on {TEAL}"),
        expand=False,
        padding=(0, 2),
        style=TEAL,
    )


def _print_cmd_help(name: str) -> None:
    data = _CMD_DOCS[name]
    console.print(_panel_title(name))
    console.print()
    console.print(Text("Usage:", style=LABEL_COLOR))
    console.print(Text(data["usage"], style=CMD_COLOR))
    console.print()
    console.print(Text("Description:", style=LABEL_COLOR))
    console.print(Text(data["desc"], style=CMD_COLOR))
    if data.get("ex"):
        console.print()
        console.print(Text("Examples:", style=LABEL_COLOR))
        for e in data["ex"]:
            console.print(Text(f"  {e}", style=DIM))
    console.print()


class HelpMixin:

    @with_category("Information")
    def do_help(self, arg: str) -> None:
        console.print()

        if arg:
            name = arg.strip()
            if name in _CMD_DOCS:
                _print_cmd_help(name)
                print_status_bar(self)
                return
            try:
                func = getattr(self, f"do_{name}")
                doc = (func.__doc__ or "No documentation available.").strip()
                console.print(_panel_title(name))
                console.print()
                console.print(Text(doc, style=CMD_COLOR))
                console.print()
                print_status_bar(self)
                return
            except AttributeError:
                close = get_close_matches(name, [m[3:] for m in dir(self) if m.startswith("do_")], n=3)
                msg = f"✖ No such command '{name}'"
                if close:
                    msg += f" (did you mean: {', '.join(close)})"
                console.print(Text(msg, style="bold red"))
                console.print()
                print_status_bar(self)
                return

        console.print(_panel_title("Argus CLI Help"))
        console.print()

        cat_w = max(len(c) for c, _ in _ENTRIES) + 2
        titles = Text()
        titles.append("Category".ljust(cat_w), style=f"bold {TEAL}")
        titles.append("Commands", style="bold white")
        console.print(titles)
        console.print()

        for cat, cmds in _ENTRIES:
            line = Text()
            line.append(cat.ljust(cat_w), style=CAT_COLOR)
            line.append(cmds, style=CMD_COLOR)
            console.print(line)

        console.print()
        console.print(Text("Tip: use 'help <command>' for detailed docs.", style=f"bold white on {TEAL}"))
        console.print()
        print_status_bar(self)
