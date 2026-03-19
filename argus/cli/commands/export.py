"""
argus.cli.commands.export
~~~~~~~~~~~~~~~~~~~~~~~~~~
`export` command — save the last run results to JSON, CSV, or TXT.
Usage:
    argus> export           # exports to all enabled formats
    argus> export json      # force JSON only
    argus> export csv       # force CSV only
    argus> export txt       # force TXT only
    argus> export json --dir /tmp/my_reports
"""
from __future__ import annotations

import argparse
import os
from cmd2 import with_argparser, with_category
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from argus.utils.report_generator import (
    generate_txt_report,
    generate_csv_report,
    generate_json_report,
    generate_base_filename,
    ensure_results_directory,
)
from argus.utils.util import clean_domain_input
from argus.config.settings import EXPORT_SETTINGS

__mixin_name__ = "ExportMixin"

TEAL = "#2EC4B6"
console = Console()


class ExportMixin:
    _export_parser = argparse.ArgumentParser(description="Export last run results")
    _export_parser.add_argument(
        "fmt", nargs="?",
        choices=["json", "csv", "txt", "all"],
        default="all",
        help="Output format (default: all enabled formats)",
    )
    _export_parser.add_argument(
        "--dir", dest="output_dir", default=None,
        help="Override output directory",
    )
    _export_parser.add_argument(
        "--filename", dest="filename", default=None,
        help="Override base filename (no extension)",
    )

    @with_argparser(_export_parser)
    @with_category("Output")
    def do_export(self, args) -> None:
        if not self.last_run_outputs:
            self.perror("Nothing has been run yet. Use 'run' first.")
            return

        if not self.target:
            self.perror("No target set. Cannot determine output path.")
            return

        domain   = clean_domain_input(self.target)
        data     = self.last_run_outputs
        modules  = list(data.keys())

        # Resolve output directory
        if args.output_dir:
            out_dir = os.path.abspath(args.output_dir)
            os.makedirs(out_dir, exist_ok=True)
        else:
            out_dir = ensure_results_directory(domain)

        base = args.filename or generate_base_filename(domain, modules)

        fmt = args.fmt or "all"
        exported: list[str] = []

        if fmt in ("txt", "all") and (fmt == "txt" or EXPORT_SETTINGS.get("enable_txt_export")):
            generate_txt_report(data, base, out_dir)
            exported.append(f"{base}.txt")

        if fmt in ("csv", "all") and (fmt == "csv" or EXPORT_SETTINGS.get("enable_csv_export")):
            generate_csv_report(data, base, out_dir)
            exported.append(f"{base}.csv")

        if fmt in ("json", "all") and (fmt == "json" or EXPORT_SETTINGS.get("enable_json_export", True)):
            generate_json_report(data, base, out_dir, self.target, modules)
            exported.append(f"{base}.json")

        if not exported:
            console.print("[yellow]No export formats enabled. Use 'export json/csv/txt' to force one.[/yellow]")
            return

        console.print()
        header = Text(" Export complete ", justify="center", style=f"bold white on {TEAL}")
        console.print(Panel(header, expand=False, padding=(0, 2), style=TEAL))
        console.print(f"[dim]Directory:[/dim] {out_dir}")
        for f in exported:
            console.print(f"  [green]✓[/green]  {f}")
        console.print()
        self._print_status_bar()
