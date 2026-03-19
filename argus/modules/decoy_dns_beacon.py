#!/usr/bin/env python3
import os
import sys
import json
import re
import time
import uuid
import requests
import urllib3
import dns.resolver
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()
resolver = dns.resolver.Resolver()

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]     Argus – Decoy DNS Beacon")
    console.print(f"[cyan]{bar}\n")

def token_file(domain):
    path = os.path.join(RESULTS_DIR, domain)
    ensure_directory_exists(path)
    return os.path.join(path, "dns_beacons.json")

def load_tokens(path):
    if os.path.exists(path):
        try:
            return json.load(open(path, "r"))
        except:
            pass
    return []

def save_tokens(path, tokens):
    with open(path, "w") as f:
        json.dump(tokens, f, indent=2)

def generate(domain, count):
    now = datetime.datetime.utcnow().isoformat()
    return [
        {"token": f"{uuid.uuid4().hex[:8]}.{domain}",
         "created": now,
         "resolved": False,
         "timestamp": None}
        for _ in range(count)
    ]

def check(token, dns_server, timeout):
    resolver.nameservers = [dns_server] if dns_server else resolver.nameservers
    resolver.lifetime = timeout
    try:
        resolver.resolve(token, "A")
        return True
    except:
        return False

def run(target, threads, opts):
    banner()
    start = time.time()
    domain = clean_domain_input(target)
    count = int(opts.get("count", 5))
    verify = bool(opts.get("verify", False))
    dns_server = opts.get("dns_server", "")
    timeout = int(opts.get("timeout", 5))
    path = token_file(domain)
    tokens = load_tokens(path)

    if verify and tokens:
        to_check = [t for t in tokens if not t["resolved"]]
        console.print(f"[white][*] Verifying [cyan]{len(to_check)}[/cyan] tokens[/white]\n")
        with Progress(
            SpinnerColumn(),
            TextColumn("[white]{task.description} {task.completed}/{task.total}"),
            BarColumn(),
            console=console,
            transient=True
        ) as prog:
            task = prog.add_task("Checking DNS…", total=len(to_check))
            with ThreadPoolExecutor(max_workers=threads) as pool:
                for t in to_check:
                    pool.submit(None)  # ensure pool exists
                checks = {pool.submit(check, t["token"], dns_server, timeout): t for t in to_check}
                for fut in as_completed(checks):
                    t = checks[fut]
                    if fut.result():
                        t["resolved"] = True
                        t["timestamp"] = datetime.datetime.utcnow().isoformat()
                    prog.advance(task)
        resolved = sum(1 for t in tokens if t["resolved"])
        pending = len(tokens) - resolved
        table = Table(header_style="bold magenta", box=box.MINIMAL)
        table.add_column("Token", style="cyan", overflow="fold")
        table.add_column("Resolved", style="green")
        table.add_column("FirstSeen", style="yellow")
        for t in tokens:
            table.add_row(t["token"], "✔" if t["resolved"] else "-", t["timestamp"] or "-")
        console.print(table)
        summary = f"Total: {len(tokens)}  Resolved: {resolved}  Pending: {pending}  Elapsed: {time.time() - start:.2f}s"
    else:
        console.print(f"[white][*] Generating [green]{count}[/green] DNS beacons for [cyan]{domain}[/cyan][/white]\n")
        new = generate(domain, count)
        tokens.extend(new)
        table = Table(header_style="bold magenta", box=box.MINIMAL)
        table.add_column("Token", style="cyan", overflow="fold")
        for t in new:
            table.add_row(t["token"])
        console.print(table)
        summary = f"Generated: {len(new)}  Total: {len(tokens)}  Elapsed: {time.time() - start:.2f}s"

    save_tokens(path, tokens)
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] DNS beacon operation completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(path, export_console.export_text())

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(tgt, thr, opts)
