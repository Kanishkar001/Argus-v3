#!/usr/bin/env python3
import os
import sys
import socket
import argparse
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from socket import getservbyport

from argus.utils.util import clean_domain_input
from argus.config.settings import DEFAULT_TIMEOUT, API_KEYS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
TEAL = "#2EC4B6"

def banner():
    console.print(f"[{TEAL}]" + "="*44)
    console.print("[cyan]      Argus - Open Ports Scanner")
    console.print(f"[{TEAL}]" + "="*44)

def parse_ports(portspec):
    parts = set()
    for p in portspec.split(","):
        if "-" in p:
            a, b = map(int, p.split("-", 1))
            parts.update(range(a, b+1))
        else:
            parts.add(int(p))
    return sorted(parts)

def scan_port(ip, port, timeout):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        try:
            data = s.recv(1024)
            banner = data.decode("utf-8", "ignore").strip() or "-"
        except:
            banner = "-"
        s.close()
        try:
            svc = getservbyport(port)
        except:
            svc = "-"
        return port, svc, banner or "-"
    except:
        return None

def shodan_lookup(ip, key):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
    try:
        r = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
        if r.status_code == 200:
            js = r.json()
            return {int(p): js.get("data", [{}])[0].get("product","-") for p in js.get("ports", [])}
    except:
        pass
    return {}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-p", "--ports", default="1-1024")
    p.add_argument("-t", "--threads", type=int, default=100)
    p.add_argument("-T", "--timeout", type=float, default=1.0)
    p.add_argument("--no-fallback", action="store_true")
    args = p.parse_args()

    banner()
    host = clean_domain_input(args.target)
    try:
        ip = socket.gethostbyname(host)
    except:
        console.print(f"[red]✖ Failed to resolve {host}[/red]")
        sys.exit(1)

    shodan_key = API_KEYS.get("SHODAN_API_KEY","")
    shodan_ports = shodan_lookup(ip, shodan_key) if shodan_key else {}
    use_scan = not args.no_fallback and (not shodan_ports or shodan_key)
    ports = parse_ports(args.ports) if use_scan else sorted(shodan_ports)

    table = Table(title=f"Open Ports – {host} ({ip})", header_style="bold magenta")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="green")
    table.add_column("Banner", style="white", overflow="fold")
    table.add_column("Source", style="yellow")

    seen = {}
    if shodan_ports:
        for port, prod in shodan_ports.items():
            seen[port] = ("-", prod, "Shodan")

    if use_scan:
        with Progress(SpinnerColumn(), TextColumn("[white]{task.description}"), BarColumn(), console=console, transient=True) as pr:
            task = pr.add_task("Scanning ports", total=len(ports))
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                futures = {pool.submit(scan_port, ip, p, args.timeout): p for p in ports}
                for fut in as_completed(futures):
                    res = fut.result()
                    if res:
                        port, svc, ban = res
                        src = "Scan"
                        if port in seen:
                            _, prev, _ = seen[port]
                            src = "Both"
                            svc = svc or prev
                        seen[port] = (svc, ban, src)
                    pr.advance(task)

    if seen:
        for port in sorted(seen):
            svc, ban, src = seen[port]
            table.add_row(str(port), svc, ban, src)
        console.print(table)
    else:
        console.print("[yellow]No open ports found[/yellow]")

    console.print("[white][*] Port scanning completed[/white]")

if __name__ == "__main__":
    main()
