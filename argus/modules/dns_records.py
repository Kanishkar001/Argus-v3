"""
argus.modules.dns_records
~~~~~~~~~~~~~~~~~~~~~~~~~~
Deep DNS enumeration module.

Improvements:
  • Extended record types: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV, TLSA, SSHFP, PTR
  • Zone transfer attempt (AXFR)
  • Wildcard DNS detection
  • DNSSEC status check
  • DNS propagation across multiple public resolvers
  • Inherits ArgusModule → structured ModuleResult
"""
from __future__ import annotations

import os
import sys
import json
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import urllib3

from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from argus.modules.base import ArgusModule
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# Extended record types
ALL_RECORD_TYPES = (
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
    "CAA", "SRV", "TLSA", "SSHFP", "PTR", "DNSKEY", "DS",
)

# Public resolvers for propagation check
PUBLIC_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
]


class DNSRecords(ArgusModule):
    name = "DNS Records — Deep Enumeration"
    description = "Comprehensive DNS analysis with zone transfer, DNSSEC, and propagation checks"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
        types_str = opts.get("types", "")
        types = tuple(map(str.upper, types_str.split(","))) if types_str else ALL_RECORD_TYPES
        domain = self.clean(target)
        do_zone_transfer = bool(int(opts.get("zone_transfer", 1)))
        do_propagation = bool(int(opts.get("propagation", 1)))
        do_wildcard = bool(int(opts.get("wildcard_check", 1)))

        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = timeout

        console.print(f"[cyan][*] Target: [bold]{domain}[/bold][/cyan]")
        console.print(f"[dim]    Record types: {', '.join(types)}[/dim]\n")

        findings: list[Finding] = []
        metadata: dict[str, Any] = {"domain": domain}

        # ── 1. Standard DNS records ───────────────────────────────────
        results: list[tuple[str, list[str]]] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[white]{task.fields[rtype]}"),
            BarColumn(),
            console=console, transient=True,
        ) as prog:
            task = prog.add_task("Querying records…", total=len(types), rtype="")
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = {pool.submit(self._get_records, resolver, domain, r): r for r in types}
                for fut in as_completed(futures):
                    rtype = futures[fut]
                    recs = fut.result()
                    results.append((rtype, recs))
                    prog.update(task, advance=1, rtype=rtype)

        # Display
        table = Table(
            title=f"DNS Records — {domain}",
            header_style="bold magenta",
            box=box.MINIMAL,
        )
        table.add_column("Type", style="cyan")
        table.add_column("Value(s)", style="green", overflow="fold")
        total_values = 0
        records_dict: dict[str, list[str]] = {}
        for rtype, recs in sorted(results, key=lambda x: x[0]):
            vals = "; ".join(recs)
            valid = recs != ["-"]
            if valid:
                total_values += len(recs)
            table.add_row(rtype, vals)
            records_dict[rtype] = recs
        console.print(table)
        metadata["records"] = records_dict

        # ── 2. Wildcard detection ─────────────────────────────────────
        if do_wildcard:
            wildcard = self._check_wildcard(domain)
            if wildcard:
                console.print(f"[yellow][!] Wildcard DNS detected: *.{domain} → {wildcard}[/yellow]")
                findings.append(Finding(
                    title="Wildcard DNS Detected",
                    severity=Severity.MEDIUM,
                    description=f"Wildcard DNS resolves *.{domain} to {wildcard}",
                    remediation="Wildcard DNS can mask subdomain takeover vulnerabilities",
                ))
                metadata["wildcard_ip"] = wildcard

        # ── 3. Zone transfer attempt ──────────────────────────────────
        if do_zone_transfer:
            console.print("[white][*] Attempting zone transfer (AXFR)...[/white]")
            ns_records = records_dict.get("NS", ["-"])
            for ns in ns_records:
                if ns == "-":
                    continue
                zt_records = self._attempt_zone_transfer(domain, ns.rstrip("."))
                if zt_records:
                    console.print(f"[bold red][!] Zone transfer SUCCESSFUL on {ns} — {len(zt_records)} records![/bold red]")
                    findings.append(Finding(
                        title="DNS Zone Transfer Allowed",
                        severity=Severity.CRITICAL,
                        description=f"Zone transfer (AXFR) succeeded on nameserver {ns}",
                        evidence=f"Retrieved {len(zt_records)} zone records",
                        remediation="Restrict zone transfers to authorized IPs. Disable AXFR on public-facing nameservers.",
                    ))
                    metadata["zone_transfer"] = {"ns": ns, "records_count": len(zt_records)}
                    break
            else:
                console.print("[green]    Zone transfer denied (good)[/green]")

        # ── 4. DNSSEC check ───────────────────────────────────────────
        console.print("[white][*] Checking DNSSEC status...[/white]")
        has_dnssec = "DNSKEY" in records_dict and records_dict["DNSKEY"] != ["-"]
        has_ds = "DS" in records_dict and records_dict["DS"] != ["-"]
        if has_dnssec or has_ds:
            console.print("[green]    DNSSEC is enabled[/green]")
            findings.append(Finding(
                title="DNSSEC Enabled",
                severity=Severity.INFO,
                description="Domain has DNSSEC records (DNSKEY/DS) configured",
            ))
        else:
            console.print("[yellow]    DNSSEC not configured[/yellow]")
            findings.append(Finding(
                title="DNSSEC Not Configured",
                severity=Severity.LOW,
                description="No DNSKEY or DS records found — DNSSEC is not enabled",
                remediation="Enable DNSSEC to protect against DNS spoofing attacks",
            ))

        # ── 5. DNS propagation ────────────────────────────────────────
        if do_propagation:
            console.print("[white][*] Checking DNS propagation...[/white]")
            prop_table = Table(
                title="DNS Propagation (A record)",
                header_style="bold magenta",
                box=box.SIMPLE,
            )
            prop_table.add_column("Resolver", style="cyan")
            prop_table.add_column("IP", style="green")
            prop_table.add_column("Status", style="yellow")
            prop_results: dict[str, str] = {}
            for name, ip in PUBLIC_RESOLVERS:
                resolved = self._query_resolver(domain, ip)
                prop_results[name] = resolved
                status = "✓" if resolved != "-" else "✗"
                prop_table.add_row(f"{name} ({ip})", resolved, status)
            console.print(prop_table)
            metadata["propagation"] = prop_results

            unique_ips = set(v for v in prop_results.values() if v != "-")
            if len(unique_ips) > 1:
                findings.append(Finding(
                    title="DNS Propagation Inconsistency",
                    severity=Severity.MEDIUM,
                    description=f"Domain resolves to different IPs across resolvers: {', '.join(unique_ips)}",
                    remediation="Check for CDN configuration or recent DNS changes",
                ))

        # ── Summary ───────────────────────────────────────────────────
        findings.append(Finding(
            title="DNS Enumeration Summary",
            severity=Severity.INFO,
            description=f"Queried {len(types)} record types, found {total_values} total records",
        ))

        summary_text = (
            f"Types: {len(types)}  |  Records: {total_values}  |  Findings: {len(findings)}"
        )
        console.print(Panel(summary_text, title="Summary", style="bold white"))
        console.print("[green][*] DNS records check completed[/green]\n")

        # Export
        if EXPORT_SETTINGS.get("enable_txt_export"):
            out = os.path.join(RESULTS_DIR, domain)
            ensure_directory_exists(out)
            export_console = Console(record=True, width=console.width)
            export_console.print(table)
            export_console.print(Panel(summary_text, title="Summary", style="bold white"))
            write_to_file(os.path.join(out, "dns_records.txt"), export_console.export_text())

        return self.make_result(target=domain, findings=findings, metadata=metadata)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _get_records(resolver: dns.resolver.Resolver, domain: str, rtype: str) -> list[str]:
        try:
            answers = resolver.resolve(domain, rtype)
            return [str(r.to_text()) for r in answers]
        except Exception:
            return ["-"]

    @staticmethod
    def _check_wildcard(domain: str) -> str | None:
        import random, string
        random_sub = "".join(random.choices(string.ascii_lowercase, k=16))
        try:
            return socket.gethostbyname(f"{random_sub}.{domain}")
        except socket.gaierror:
            return None

    @staticmethod
    def _attempt_zone_transfer(domain: str, ns: str) -> list[str]:
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            return [str(name) for name in zone.nodes.keys()]
        except Exception:
            return []

    @staticmethod
    def _query_resolver(domain: str, resolver_ip: str) -> str:
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [resolver_ip]
            r.lifetime = 5
            answers = r.resolve(domain, "A")
            return str(answers[0])
        except Exception:
            return "-"


# ── Backward-compatible entry points ─────────────────────────────────────────

def run(target, threads, opts):
    """Legacy entry point for the runner."""
    instance = DNSRecords()
    instance.start_time = time.time()
    return instance.run(target, threads, opts)


if __name__ == "__main__":
    DNSRecords.entrypoint()
