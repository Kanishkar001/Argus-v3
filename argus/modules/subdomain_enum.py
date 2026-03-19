"""
argus.modules.subdomain_enum
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Multi-source subdomain enumeration with DNS resolution verification.

Sources:
  • crt.sh (Certificate Transparency)
  • HackerTarget (passive DNS)
  • DNS brute-force (common prefixes)

Improvements over original:
  • 3 data sources instead of 1
  • DNS resolution verification (alive check)
  • Wildcard detection
  • Concurrent execution
  • Inherits ArgusModule → structured ModuleResult
"""
from __future__ import annotations

import concurrent.futures
import dns.resolver
import re
import socket
import time
from typing import Any

import requests
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from argus.modules.base import ArgusModule, retry
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT

console = Console()

# ── Common subdomain prefixes for brute-force ────────────────────────────────
COMMON_PREFIXES = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api",
    "dev", "staging", "test", "qa", "beta", "alpha", "demo", "app",
    "admin", "portal", "blog", "shop", "store", "cdn", "static", "assets",
    "media", "img", "images", "docs", "help", "support", "status",
    "vpn", "remote", "gateway", "proxy", "secure", "login", "sso",
    "auth", "oauth", "id", "accounts", "my", "dashboard", "panel",
    "cp", "cpanel", "whm", "plesk", "webdisk", "cloud", "aws",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "search", "elk", "kibana", "grafana", "prometheus", "monitor",
    "nagios", "zabbix", "sentry", "log", "logs", "backup", "bak",
    "internal", "intranet", "extranet", "partner", "b2b", "b2c",
    "m", "mobile", "wap", "api-v1", "api-v2", "v1", "v2", "v3",
    "old", "new", "legacy", "www2", "www3", "web", "web1", "web2",
    "s1", "s2", "s3", "node1", "node2", "srv", "server",
    "exchange", "owa", "autodiscover", "lyncdiscover", "sip",
    "calendar", "meet", "conference", "video", "chat",
]


class SubdomainEnum(ArgusModule):
    name = "Subdomain Enumeration"
    description = "Multi-source subdomain discovery with DNS verification"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        domain = self.clean(target)
        timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
        threads = max(1, min(threads, 50))
        do_bruteforce = bool(int(opts.get("bruteforce", 1)))
        do_resolve = bool(int(opts.get("resolve", 1)))

        console.print(f"[cyan][*] Target: [bold]{domain}[/bold][/cyan]")
        console.print(f"[dim]    Threads: {threads}  |  Bruteforce: {do_bruteforce}  |  Resolve: {do_resolve}[/dim]\n")

        all_subdomains: set[str] = set()

        # ── Source 1: crt.sh ──────────────────────────────────────────
        console.print("[white][*] Querying crt.sh (Certificate Transparency)...[/white]")
        crt_subs = self._query_crtsh(domain, timeout)
        all_subdomains.update(crt_subs)
        console.print(f"[green]    Found {len(crt_subs)} subdomains from crt.sh[/green]")

        # ── Source 2: HackerTarget ────────────────────────────────────
        console.print("[white][*] Querying HackerTarget...[/white]")
        ht_subs = self._query_hackertarget(domain, timeout)
        all_subdomains.update(ht_subs)
        console.print(f"[green]    Found {len(ht_subs)} subdomains from HackerTarget[/green]")

        # ── Source 3: DNS brute-force ─────────────────────────────────
        if do_bruteforce:
            console.print(f"[white][*] DNS brute-force ({len(COMMON_PREFIXES)} prefixes)...[/white]")
            brute_subs = self._bruteforce_dns(domain, threads, timeout)
            all_subdomains.update(brute_subs)
            console.print(f"[green]    Found {len(brute_subs)} subdomains via brute-force[/green]")

        # ── Wildcard detection ────────────────────────────────────────
        wildcard_ip = self._detect_wildcard(domain)
        if wildcard_ip:
            console.print(f"[yellow][!] Wildcard DNS detected: *.{domain} → {wildcard_ip}[/yellow]")

        # ── DNS resolution ────────────────────────────────────────────
        resolved: dict[str, str] = {}
        if do_resolve and all_subdomains:
            console.print(f"[white][*] Resolving {len(all_subdomains)} subdomains...[/white]")
            resolved = self._resolve_subdomains(all_subdomains, threads, wildcard_ip)
            console.print(f"[green]    {len(resolved)} subdomains resolved to IPs[/green]")

        # ── Results table ─────────────────────────────────────────────
        console.print()
        table = Table(
            title=f"Subdomains — {domain} ({len(all_subdomains)} unique)",
            header_style="bold magenta",
            box=box.MINIMAL_HEAVY_HEAD,
        )
        table.add_column("Subdomain", style="cyan", overflow="fold")
        table.add_column("IP Address", style="green")
        table.add_column("Status", style="yellow")

        for sub in sorted(all_subdomains):
            ip = resolved.get(sub, "-")
            if ip == "-":
                status = "Unresolved"
            elif wildcard_ip and ip == wildcard_ip:
                status = "Wildcard"
            else:
                status = "Active"
            table.add_row(sub, ip, status)

        console.print(table)

        # ── Build findings ────────────────────────────────────────────
        findings: list[Finding] = []
        active_count = sum(1 for ip in resolved.values() if ip and ip != wildcard_ip)

        findings.append(Finding(
            title="Subdomain Enumeration Summary",
            severity=Severity.INFO,
            description=f"Found {len(all_subdomains)} unique subdomains, {active_count} actively resolving",
            evidence=f"Sources: crt.sh({len(crt_subs)}), HackerTarget({len(ht_subs)})"
                     + (f", Brute-force({len(brute_subs)})" if do_bruteforce else ""),
        ))

        if wildcard_ip:
            findings.append(Finding(
                title="Wildcard DNS Detected",
                severity=Severity.MEDIUM,
                description=f"Wildcard DNS is configured for *.{domain}",
                evidence=f"Random subdomain resolved to {wildcard_ip}",
                remediation="Wildcard DNS can mask subdomain takeover and enable enumeration evasion",
            ))

        self.summary(f"Subdomains: {len(all_subdomains)}  |  Active: {active_count}")
        console.print("[green][*] Subdomain enumeration completed[/green]\n")

        return self.make_result(target=domain, findings=findings, metadata={
            "subdomains": sorted(all_subdomains),
            "resolved": resolved,
            "wildcard_ip": wildcard_ip,
        })

    # ── Data sources ─────────────────────────────────────────────────────

    @retry(max_attempts=2, delay=2.0, exceptions=(requests.RequestException,))
    def _query_crtsh(self, domain: str, timeout: int) -> set[str]:
        subdomains: set[str] = set()
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self.session.get(url, timeout=timeout)
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(f".{domain}") and "*" not in sub:
                            subdomains.add(sub)
        except Exception as exc:
            self.logger.warning("crt.sh query failed: %s", exc)
        return subdomains

    @retry(max_attempts=2, delay=2.0, exceptions=(requests.RequestException,))
    def _query_hackertarget(self, domain: str, timeout: int) -> set[str]:
        subdomains: set[str] = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = self.session.get(url, timeout=timeout)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().splitlines():
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip().lower()
                        if sub and sub.endswith(f".{domain}"):
                            subdomains.add(sub)
        except Exception as exc:
            self.logger.warning("HackerTarget query failed: %s", exc)
        return subdomains

    def _bruteforce_dns(self, domain: str, threads: int, timeout: int) -> set[str]:
        found: set[str] = set()
        resolver = dns.resolver.Resolver()
        resolver.lifetime = min(timeout, 5)

        def _check(prefix: str) -> str | None:
            fqdn = f"{prefix}.{domain}"
            try:
                answers = resolver.resolve(fqdn, "A")
                if answers:
                    return fqdn
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_check, p): p for p in COMMON_PREFIXES}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    found.add(result)
        return found

    def _detect_wildcard(self, domain: str) -> str | None:
        """Detect wildcard DNS by resolving a random subdomain."""
        import random
        import string
        random_sub = "".join(random.choices(string.ascii_lowercase, k=16))
        fqdn = f"{random_sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return ip
        except socket.gaierror:
            return None

    def _resolve_subdomains(
        self, subdomains: set[str], threads: int, wildcard_ip: str | None
    ) -> dict[str, str]:
        resolved: dict[str, str] = {}

        def _resolve(sub: str) -> tuple[str, str]:
            try:
                ip = socket.gethostbyname(sub)
                return sub, ip
            except socket.gaierror:
                return sub, "-"

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for sub, ip in pool.map(_resolve, subdomains):
                if ip != "-":
                    resolved[sub] = ip
        return resolved


if __name__ == "__main__":
    SubdomainEnum.entrypoint()
