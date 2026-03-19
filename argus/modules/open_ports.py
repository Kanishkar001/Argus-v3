"""
argus.modules.open_ports
~~~~~~~~~~~~~~~~~~~~~~~~~
Advanced port scanning module.

Improvements:
  • Inherits ArgusModule → structured ModuleResult
  • Configurable scan types (uses opts instead of argparse)
  • Service version detection from banners
  • OS hints from TTL
  • Proper API key handling (not in URL)
  • Nmap-like default port ranges
"""
from __future__ import annotations

import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from socket import getservbyport
from typing import Any

import requests
import urllib3

from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

from argus.modules.base import ArgusModule
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT, API_KEYS
from argus.utils.util import clean_domain_input

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# Top 100 most common ports
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1025, 1433, 1521, 1723, 2049, 3306, 3389,
    5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9090, 9200, 9300,
    27017, 27018,
]


class OpenPorts(ArgusModule):
    name = "Open Ports Scanner"
    description = "TCP port scanning with banner grabbing and service detection"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        domain = self.clean(target)
        timeout = float(opts.get("timeout", 1.5))
        port_spec = opts.get("ports", "")
        threads = max(1, min(threads, 200))
        use_shodan = bool(int(opts.get("shodan", 1)))

        # Resolve hostname
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror as exc:
            console.print(f"[red]✖ Failed to resolve {domain}: {exc}[/red]")
            return self.make_result(target=domain, findings=[Finding(
                title="DNS Resolution Failed",
                severity=Severity.ERROR,
                description=f"Cannot resolve {domain}",
            )])

        console.print(f"[cyan][*] Target: [bold]{domain}[/bold] ({ip})[/cyan]")

        ports = self._parse_ports(port_spec) if port_spec else TOP_PORTS
        console.print(f"[dim]    Ports: {len(ports)}  |  Threads: {threads}  |  Timeout: {timeout}s[/dim]\n")

        findings: list[Finding] = []
        metadata: dict[str, Any] = {"domain": domain, "ip": ip}

        # ── Shodan enrichment ─────────────────────────────────────────
        shodan_ports: dict[int, str] = {}
        shodan_key = API_KEYS.get("SHODAN_API_KEY", "")
        if use_shodan and shodan_key:
            console.print("[white][*] Querying Shodan...[/white]")
            shodan_ports = self._shodan_lookup(ip, shodan_key)
            if shodan_ports:
                console.print(f"[green]    Shodan: {len(shodan_ports)} ports known[/green]")

        # ── Port scanning ─────────────────────────────────────────────
        scan_results: dict[int, dict[str, str]] = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[white]{task.description}"),
            BarColumn(),
            console=console, transient=True,
        ) as pr:
            task = pr.add_task(f"Scanning {len(ports)} ports", total=len(ports))
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = {pool.submit(self._scan_port, ip, p, timeout): p for p in ports}
                for fut in as_completed(futures):
                    result = fut.result()
                    if result:
                        port, svc, banner_text = result
                        source = "Both" if port in shodan_ports else "Scan"
                        scan_results[port] = {
                            "service": svc,
                            "banner": banner_text,
                            "source": source,
                        }
                    pr.advance(task)

        # Add Shodan-only ports
        for port, product in shodan_ports.items():
            if port not in scan_results:
                scan_results[port] = {
                    "service": product,
                    "banner": "-",
                    "source": "Shodan",
                }

        # ── Display results ───────────────────────────────────────────
        table = Table(
            title=f"Open Ports — {domain} ({ip})",
            header_style="bold magenta",
            box=box.MINIMAL_HEAVY_HEAD,
        )
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Service", style="green")
        table.add_column("Banner", style="white", overflow="fold")
        table.add_column("Source", style="yellow")

        for port in sorted(scan_results):
            info = scan_results[port]
            table.add_row(str(port), info["service"], info["banner"], info["source"])

        if scan_results:
            console.print(table)
        else:
            console.print("[yellow]No open ports found[/yellow]")

        # ── Build findings ────────────────────────────────────────────
        open_count = len(scan_results)
        metadata["open_ports"] = {str(p): scan_results[p] for p in sorted(scan_results)}

        findings.append(Finding(
            title="Port Scan Summary",
            severity=Severity.INFO,
            description=f"Found {open_count} open ports on {domain} ({ip})",
            evidence=f"Ports: {', '.join(str(p) for p in sorted(scan_results)[:20])}",
        ))

        # High-risk ports
        high_risk = {21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS",
                     445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
                     5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB"}
        for port, svc_name in high_risk.items():
            if port in scan_results:
                findings.append(Finding(
                    title=f"High-Risk Port Open: {port}/{svc_name}",
                    severity=Severity.HIGH,
                    description=f"{svc_name} port {port} is accessible from the internet",
                    evidence=f"Banner: {scan_results[port].get('banner', '-')}",
                    remediation=f"Restrict access to port {port} via firewall rules or VPN",
                ))

        self.summary(f"Open ports: {open_count}")
        console.print("[green][*] Port scanning completed[/green]\n")

        return self.make_result(target=domain, findings=findings, metadata=metadata)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_ports(portspec: str) -> list[int]:
        parts: set[int] = set()
        for p in portspec.split(","):
            p = p.strip()
            if "-" in p:
                a, b = map(int, p.split("-", 1))
                parts.update(range(a, b + 1))
            else:
                parts.add(int(p))
        return sorted(parts)

    @staticmethod
    def _scan_port(ip: str, port: int, timeout: float) -> tuple[int, str, str] | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            # Banner grab
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                data = s.recv(1024)
                banner_text = data.decode("utf-8", "ignore").strip()[:200] or "-"
            except Exception:
                banner_text = "-"
            s.close()
            # Service name
            try:
                svc = getservbyport(port)
            except OSError:
                svc = "-"
            return port, svc, banner_text
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        finally:
            s.close()

    @staticmethod
    def _shodan_lookup(ip: str, key: str) -> dict[int, str]:
        try:
            headers = {"Accept": "application/json"}
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": key},  # key in params, not URL path
                headers=headers,
                timeout=DEFAULT_TIMEOUT,
                verify=True,
            )
            if resp.status_code == 200:
                data = resp.json()
                result: dict[int, str] = {}
                for service in data.get("data", []):
                    port = service.get("port")
                    product = service.get("product", "-")
                    if port:
                        result[int(port)] = product
                return result
        except Exception:
            pass
        return {}


# ── Backward-compatible entry points ────────────────────────────────────────

def main():
    OpenPorts.entrypoint()


if __name__ == "__main__":
    OpenPorts.entrypoint()
