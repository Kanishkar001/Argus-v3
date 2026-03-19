"""
argus.cli.commands.scan
~~~~~~~~~~~~~~~~~~~~~~~~
`scan` — opinionated all-in-one recon workflow.
Runs a curated set of modules against a target in a single command,
grouped by phase (recon → web → security), with progress tracking
and a final risk summary.

Usage:
    argus> scan example.com
    argus> scan example.com --profile quick
    argus> scan example.com --profile deep
    argus> scan example.com --only network
    argus> scan example.com --skip security
"""
from __future__ import annotations

import argparse
import time
from typing import List

from cmd2 import with_argparser, with_category
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from argus.core.runner import run_modules, execute_script, parse_output_severity
from argus.core.catalog_cache import tools_mapping, tools
from argus.utils.util import clean_domain_input

__mixin_name__ = "ScanMixin"

TEAL = "#2EC4B6"
console = Console()

# ── Preset module groups by name fragment ────────────────────────────────────
SCAN_PROFILES: dict[str, dict[str, list[str]]] = {
    "quick": {
        "Network": [
            "DNS Records", "WHOIS Lookup", "SSL Expiry Alert",
            "Open Ports Scan", "HTTP/2 & HTTP/3 Support",
        ],
        "Web": [
            "HTTP Headers", "HTTP Security Features", "Technology Stack Detection",
            "Redirect Chain", "Robots.txt Analyzer",
        ],
        "Security": [
            "SPF / DKIM / DMARC Validator", "Subdomain Enumeration",
            "Firewall Detection", "CORS Misconfiguration Scanner",
        ],
    },
    "deep": {
        "Network": [
            "DNS Records", "DNSSEC Check", "WHOIS Lookup", "RDAP Lookup",
            "SSL Chain Analysis", "SSL Expiry Alert", "TLS Cipher Suites",
            "TLS Handshake Simulation", "Open Ports Scan", "Traceroute",
            "ASN Lookup", "BGP Route Analysis", "CDN Detection",
        ],
        "Web": [
            "HTTP Headers", "HTTP Security Features", "Technology Stack Detection",
            "CMS Detection", "Redirect Chain", "Robots.txt Analyzer",
            "Sitemap Parsing", "Cookies Analyzer", "JavaScript File Analyzer",
            "CORS Misconfiguration Scanner", "CSP Deep Analyzer",
            "Content Discovery", "Email Harvesting",
        ],
        "Security": [
            "SPF / DKIM / DMARC Validator", "Subdomain Enumeration",
            "Subdomain Takeover", "Firewall Detection", "Malware & Phishing Check",
            "Data Leak Detection", "Exposed Environment Files",
            "Git Repository Exposure Check", "CT Log Query",
        ],
    },
}
# quick is also the default
SCAN_PROFILES["default"] = SCAN_PROFILES["quick"]


def _resolve_module_ids(name_list: list[str]) -> list[str]:
    """Resolve module names to IDs via exact then partial match."""
    id_list: list[str] = []
    name_lower_map = {t["name"].lower(): t["number"] for t in tools}
    for name in name_list:
        nl = name.lower()
        if nl in name_lower_map:
            id_list.append(name_lower_map[nl])
            continue
        # Partial match fallback
        partial = next((v for k, v in name_lower_map.items() if nl in k), None)
        if partial:
            id_list.append(partial)
    return id_list


def _header(txt: str) -> Panel:
    return Panel(
        Text(f" {txt} ", justify="center", style=f"bold white on {TEAL}"),
        expand=False, padding=(0, 2), style=TEAL,
    )


class ScanMixin:
    _scan_parser = argparse.ArgumentParser(
        description="All-in-one recon scan workflow"
    )
    _scan_parser.add_argument(
        "target", nargs="?", default=None,
        help="Target domain or IP (overrides current target)",
    )
    _scan_parser.add_argument(
        "--profile", "-p",
        choices=["quick", "deep", "default"],
        default="quick",
        help="Scan preset (default: quick)",
    )
    _scan_parser.add_argument(
        "--only",
        choices=["network", "web", "security"],
        default=None,
        help="Run only one phase",
    )
    _scan_parser.add_argument(
        "--skip",
        choices=["network", "web", "security"],
        default=None,
        help="Skip one phase",
    )
    _scan_parser.add_argument(
        "--threads", "-t", type=int, default=None,
        help="Override thread count",
    )
    _scan_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would run without executing",
    )

    @with_argparser(_scan_parser)
    @with_category("Execution")
    def do_scan(self, args) -> None:
        # Target resolution
        if args.target:
            self.target = args.target
        if not self.target:
            self._prompt_target_if_needed()
        if not self.target:
            self.perror("No target set.")
            return

        domain  = clean_domain_input(self.target)
        profile = SCAN_PROFILES.get(args.profile, SCAN_PROFILES["quick"])
        threads = args.threads or self.threads or 4

        # Phase filtering
        phases: dict[str, list[str]] = {}
        for phase_name, module_names in profile.items():
            key = phase_name.lower()
            if args.only and args.only != key:
                continue
            if args.skip and args.skip == key:
                continue
            phases[phase_name] = module_names

        # Resolve IDs
        phase_ids: dict[str, list[str]] = {
            phase: _resolve_module_ids(names)
            for phase, names in phases.items()
        }
        total = sum(len(ids) for ids in phase_ids.values())

        console.print()
        console.print(_header(f" Argus Scan — {domain} "))
        console.print()

        # Show plan
        plan_table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {TEAL}")
        plan_table.add_column("Phase",   style="cyan",  width=12)
        plan_table.add_column("Modules", style="white")
        for phase, ids in phase_ids.items():
            mod_names = [tools_mapping[i]["name"] for i in ids if i in tools_mapping]
            plan_table.add_row(phase, ", ".join(mod_names))
        console.print(plan_table)
        console.print(f"[dim]Profile: {args.profile}  |  Target: {domain}  |  Threads: {threads}  |  Total modules: {total}[/dim]\n")

        if args.dry_run:
            console.print("[yellow]DRY RUN — no modules executed.[/yellow]")
            self._print_status_bar()
            return

        # Execute phase by phase
        all_outputs: dict[str, str] = {}
        all_runtimes: list[tuple] = []
        scan_start = time.time()

        for phase, ids in phase_ids.items():
            if not ids:
                continue
            console.print(f"\n[bold {TEAL}]── {phase.upper()} PHASE ──[/bold {TEAL}]")
            run_modules(
                ids,
                self.api_status,
                self.target,
                threads,
                f"SCAN_{phase.upper()}",
                self,
            )
            all_outputs.update(getattr(self, "last_run_outputs", {}))
            all_runtimes.extend(getattr(self, "last_run_runtimes", []))

        # Persist combined results
        self.last_run_outputs  = all_outputs
        self.last_run_runtimes = all_runtimes

        # ── Risk summary ───────────────────────────────────────────────────
        elapsed = time.time() - scan_start
        alerts  = [r for r in all_runtimes if r[1] == "ALERT"]
        warns   = [r for r in all_runtimes if r[1] == "WARN"]

        console.print()
        summary = Table(title="Scan Summary", box=box.SIMPLE_HEAVY)
        summary.add_column("Metric",  style="cyan", no_wrap=True)
        summary.add_column("Value",   style="white")
        summary.add_row("Target",        domain)
        summary.add_row("Profile",       args.profile)
        summary.add_row("Modules run",   str(len(all_runtimes)))
        summary.add_row("Total time",    f"{elapsed:.1f}s")
        summary.add_row(
            "Alerts",
            Text(str(len(alerts)), style="bold red" if alerts else "green"),
        )
        summary.add_row(
            "Warnings",
            Text(str(len(warns)),  style="bold yellow" if warns else "green"),
        )
        console.print(summary)

        if alerts:
            console.print(f"\n[bold red][!] Critical findings:[/bold red]")
            for name, _, elapsed_m in alerts:
                console.print(f"   [red]•[/red] {name}")

        console.print(
            f"\n[dim]Run [bold]export json[/bold] to save results. "
            f"Run [bold]stats[/bold] for detailed timing.[/dim]"
        )
        console.print()
        self._print_status_bar()
