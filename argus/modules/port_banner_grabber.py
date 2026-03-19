"""
argus.modules.port_banner_grabber
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Connects to open ports and grabs raw service banners.
Identifies service type, version hints, and flags risky services.
Much faster and stealthier than full nmap — no subprocess needed.
"""
from __future__ import annotations

import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.modules.base import ArgusModule
from argus.utils.util import clean_domain_input, resolve_to_ip

console = Console()

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    587, 993, 995, 1433, 1521, 2181, 3000, 3306,
    3389, 4200, 5432, 5900, 6379, 7001, 8080,
    8443, 8888, 9200, 9300, 27017,
]

RISKY_PORTS = {
    21:    ("FTP",         "Plaintext credentials"),
    23:    ("Telnet",      "Unencrypted remote access"),
    445:   ("SMB",         "Common ransomware target"),
    1433:  ("MSSQL",       "Database exposed"),
    1521:  ("Oracle DB",   "Database exposed"),
    2181:  ("ZooKeeper",   "Often unauthenticated"),
    3306:  ("MySQL",       "Database exposed"),
    3389:  ("RDP",         "Brute-force target"),
    5432:  ("PostgreSQL",  "Database exposed"),
    5900:  ("VNC",         "Remote desktop exposed"),
    6379:  ("Redis",       "Often unauthenticated"),
    7001:  ("WebLogic",    "Known exploit surface"),
    9200:  ("Elasticsearch", "Often unauthenticated"),
    27017: ("MongoDB",     "Often unauthenticated"),
}

SERVICE_SIGNATURES: list[tuple[bytes, str]] = [
    (b"SSH-",        "SSH"),
    (b"220 ",        "FTP/SMTP"),
    (b"* OK ",       "IMAP"),
    (b"+OK ",        "POP3"),
    (b"HTTP/",       "HTTP"),
    (b"<html",       "HTTP (HTML)"),
    (b"220-",        "SMTP"),
    (b"RFB ",        "VNC"),
    (b"\xff\xfb",    "Telnet"),
    (b"AMQP",        "RabbitMQ"),
    (b"Redis",       "Redis"),
    (b"\x4a\x44\x42\x43", "JDBC/Java"),
]


@dataclass
class BannerResult:
    port:    int
    state:   str          # open / closed / filtered
    banner:  str = ""
    service: str = ""
    risk:    str = ""


def grab_banner(ip: str, port: int, timeout: float, use_tls: bool = False) -> BannerResult:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if use_tls or port in (443, 8443, 465, 993, 995):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            except ssl.SSLError:
                pass

        # Send a nudge to elicit a banner (HTTP for web ports)
        if port in (80, 8080, 8000, 3000, 4200, 8888):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port in (443, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        try:
            raw = sock.recv(1024)
        except socket.timeout:
            raw = b""

        sock.close()

        banner_text = ""
        service = ""
        if raw:
            # Detect service from signature
            for sig, svc in SERVICE_SIGNATURES:
                if raw.startswith(sig) or sig in raw[:64]:
                    service = svc
                    break
            banner_text = raw[:256].decode("utf-8", errors="replace").strip()

        # Known risky port label
        risk = ""
        if port in RISKY_PORTS:
            svc_name, risk = RISKY_PORTS[port]
            if not service:
                service = svc_name

        return BannerResult(
            port=port, state="open",
            banner=banner_text[:120].replace("\n", " ").replace("\r", ""),
            service=service,
            risk=risk,
        )

    except (ConnectionRefusedError, OSError):
        return BannerResult(port=port, state="closed")
    except socket.timeout:
        return BannerResult(port=port, state="filtered")
    except Exception as e:
        return BannerResult(port=port, state="error", banner=str(e)[:60])


class PortBannerGrabber(ArgusModule):
    name = "Port Banner Grabber"
    description = "Grab service banners from open ports without subprocess"

    def run(self, target: str, threads: int, opts: dict) -> None:
        self.banner()
        domain = self.clean(target)
        timeout = float(opts.get("timeout", 3))
        threads = max(1, min(threads, 50))

        # Parse ports option
        ports_opt = opts.get("ports", "")
        if ports_opt:
            try:
                ports = [int(p.strip()) for p in str(ports_opt).split(",") if p.strip().isdigit()]
            except ValueError:
                ports = DEFAULT_PORTS
        else:
            ports = DEFAULT_PORTS

        console.print(f"[cyan][*] Target: [bold]{domain}[/bold][/cyan]")

        ip = resolve_to_ip(domain)
        if not ip:
            console.print("[bold red][!] Could not resolve domain to IP.[/bold red]")
            return

        console.print(f"[cyan][*] IP: {ip}  |  Scanning {len(ports)} ports  |  Threads: {threads}[/cyan]\n")

        results: list[BannerResult] = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(grab_banner, ip, p, timeout): p for p in ports}
            done = 0
            for fut in as_completed(futures):
                result = fut.result()
                results.append(result)
                done += 1
                if result.state == "open":
                    svc = f" [{result.service}]" if result.service else ""
                    console.print(f"  [green]OPEN[/green]  {result.port:>5}{svc}")

        open_results = sorted(
            [r for r in results if r.state == "open"],
            key=lambda r: r.port
        )

        if not open_results:
            console.print(Panel("[green]No open ports found in the scanned range.[/green]",
                                title="Result", style="green"))
            self.summary(f"Scanned: {len(ports)} ports")
            return

        console.print()
        table = Table(
            title=f"Open Ports — {domain} ({ip})",
            header_style="bold magenta",
            box=box.MINIMAL_HEAVY_HEAD,
        )
        table.add_column("Port",    style="bold cyan", width=7)
        table.add_column("Service", style="white",     width=16)
        table.add_column("Banner",  style="dim",       overflow="fold")
        table.add_column("Risk",    style="bold red",  width=28)

        for r in open_results:
            risk_style = "bold red" if r.risk else "green"
            table.add_row(
                str(r.port),
                r.service or "—",
                r.banner or "—",
                r.risk or "—",
                style=None,
            )

        console.print(table)

        risky = [r for r in open_results if r.risk]
        if risky:
            console.print(f"\n[bold red][!] {len(risky)} high-risk service(s) exposed:[/bold red]")
            for r in risky:
                console.print(f"   Port {r.port} ({r.service}) — {r.risk}")
        else:
            console.print(f"\n[green][+] {len(open_results)} open port(s). No high-risk services detected.[/green]")

        self.summary(f"Open: {len(open_results)}/{len(ports)}")
        console.print("[green][*] Port banner grab complete[/green]\n")


if __name__ == "__main__":
    PortBannerGrabber.entrypoint()
