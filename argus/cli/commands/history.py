"""
argus.cli.commands.history
~~~~~~~~~~~~~~~~~~~~~~~~~~~
`history`  — show the last N run results with timing and severity.
`stats`    — aggregate stats: module counts, run times, severity breakdown.
`viewout`  — print cached output from a specific module name.
`grepout`  — grep cached output across all last-run modules.
"""
from __future__ import annotations

import argparse
import re
from cmd2 import with_argparser, with_category
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argus.core.runner import parse_output_severity

__mixin_name__ = "HistoryMixin"

TEAL   = "#2EC4B6"
SEV_STYLE = {
    "ALERT": "bold red",
    "WARN":  "bold yellow",
    "OK":    "bold green",
    "INFO":  "dim white",
}
console = Console()


def _header(txt: str) -> Panel:
    return Panel(
        Text(f" {txt} ", justify="center", style=f"bold white on {TEAL}"),
        expand=False, padding=(0, 2), style=TEAL,
    )


class HistoryMixin:

    # ── history ──────────────────────────────────────────────────────────
    _history_parser = argparse.ArgumentParser(description="Show recent run history")
    _history_parser.add_argument(
        "n", nargs="?", type=int, default=10,
        help="Number of recent modules to show (default 10)",
    )
    _history_parser.add_argument(
        "--severity", choices=["ALERT", "WARN", "OK", "INFO"],
        help="Filter by severity level",
    )

    @with_argparser(_history_parser)
    @with_category("Output")
    def do_history(self, args) -> None:
        runtimes = getattr(self, "last_run_runtimes", [])
        if not runtimes:
            self.perror("No runs recorded yet.")
            return

        rows = runtimes[-args.n:]
        if args.severity:
            rows = [r for r in rows if r[1] == args.severity]

        console.print()
        console.print(_header(" Run History "))
        console.print()

        table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan")
        table.add_column("#",         width=4,  style="dim")
        table.add_column("Module",    min_width=28)
        table.add_column("Severity",  width=10)
        table.add_column("Time (s)",  width=10)

        for i, (name, sev, elapsed) in enumerate(rows, 1):
            sev_styled = Text(sev, style=SEV_STYLE.get(sev, "white"))
            table.add_row(
                str(i),
                name,
                sev_styled,
                f"{elapsed:.2f}",
            )

        console.print(table)
        console.print()
        self._print_status_bar()

    # ── stats ─────────────────────────────────────────────────────────────
    @with_category("Output")
    def do_stats(self, _line) -> None:
        runtimes = getattr(self, "last_run_runtimes", [])
        outputs  = getattr(self, "last_run_outputs", {})

        console.print()
        console.print(_header(" Run Statistics "))
        console.print()

        if not runtimes:
            console.print("[dim]No runs yet.[/dim]")
            console.print()
            self._print_status_bar()
            return

        total_time   = sum(r[2] for r in runtimes)
        severities   = [r[1] for r in runtimes]
        sev_counts   = {s: severities.count(s) for s in ("ALERT", "WARN", "OK", "INFO")}
        slowest      = max(runtimes, key=lambda r: r[2])
        fastest      = min(runtimes, key=lambda r: r[2])
        total_lines  = sum(len(o.splitlines()) for o in outputs.values())

        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("Metric",    style="cyan",  no_wrap=True)
        table.add_column("Value",     style="white")

        table.add_row("Modules run",      str(len(runtimes)))
        table.add_row("Total runtime",    f"{total_time:.2f}s")
        table.add_row("Avg per module",   f"{total_time/len(runtimes):.2f}s")
        table.add_row("Slowest module",   f"{slowest[0]}  ({slowest[2]:.2f}s)")
        table.add_row("Fastest module",   f"{fastest[0]}  ({fastest[2]:.2f}s)")
        table.add_row("Total output lines", str(total_lines))
        table.add_row("",                 "")
        for sev, count in sev_counts.items():
            if count:
                styled = Text(f"{count}  {sev}", style=SEV_STYLE.get(sev, "white"))
                table.add_row(f"Severity: {sev}", styled)

        # Favorite usage
        favs = getattr(self, "favorite_modules", set())
        table.add_row("Saved favorites", str(len(favs)))
        table.add_row("Target",          self.target or "—")

        console.print(table)
        console.print()
        self._print_status_bar()

    # ── viewout ───────────────────────────────────────────────────────────
    _viewout_parser = argparse.ArgumentParser(description="View cached output")
    _viewout_parser.add_argument(
        "module", nargs="?", default=None,
        help="Module name fragment (omit to list available)",
    )

    @with_argparser(_viewout_parser)
    @with_category("Output")
    def do_viewout(self, args) -> None:
        outputs = getattr(self, "last_run_outputs", {})
        if not outputs:
            self.perror("No output cached. Run a module first.")
            return

        if not args.module:
            console.print()
            console.print(_header(" Cached Outputs "))
            console.print()
            for i, name in enumerate(outputs, 1):
                lines = len(outputs[name].splitlines())
                console.print(f"  [cyan]{i:>3}[/cyan]  {name}  [dim]({lines} lines)[/dim]")
            console.print()
            console.print("[dim]Use: viewout <module name fragment>[/dim]")
            console.print()
            return

        frag = args.module.lower()
        matches = {k: v for k, v in outputs.items() if frag in k.lower()}

        if not matches:
            self.perror(f"No cached output matching '{args.module}'.")
            return

        for name, text in matches.items():
            console.print()
            console.print(_header(f" {name} "))
            console.print(text)

        console.print()

    # ── grepout ───────────────────────────────────────────────────────────
    _grepout_parser = argparse.ArgumentParser(description="Search cached output")
    _grepout_parser.add_argument("pattern", help="Regex or plain text to search")
    _grepout_parser.add_argument(
        "-i", "--ignore-case", action="store_true", help="Case-insensitive match",
    )
    _grepout_parser.add_argument(
        "-c", "--count", action="store_true", help="Show match counts only",
    )

    @with_argparser(_grepout_parser)
    @with_category("Output")
    def do_grepout(self, args) -> None:
        outputs = getattr(self, "last_run_outputs", {})
        if not outputs:
            self.perror("No output cached. Run a module first.")
            return

        flags   = re.IGNORECASE if args.ignore_case else 0
        try:
            rx = re.compile(args.pattern, flags)
        except re.error as e:
            self.perror(f"Invalid regex: {e}")
            return

        console.print()
        total_hits = 0
        for name, text in outputs.items():
            hits = [(i + 1, line) for i, line in enumerate(text.splitlines())
                    if rx.search(line)]
            if hits:
                total_hits += len(hits)
                console.print(f"[bold cyan]{name}[/bold cyan]  [dim]({len(hits)} match(es))[/dim]")
                if not args.count:
                    for lineno, line in hits:
                        highlighted = rx.sub(
                            lambda m: f"[bold yellow]{m.group()}[/bold yellow]", line
                        )
                        console.print(f"  [dim]{lineno:>4}:[/dim]  {highlighted}")
                console.print()

        if total_hits == 0:
            console.print(f"[dim]No matches for '{args.pattern}'.[/dim]")
        else:
            console.print(f"[green]Total matches: {total_hits}[/green]")

        console.print()
        self._print_status_bar()
