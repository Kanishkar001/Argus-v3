#!/usr/bin/env python3
import os
import sys
import json
import time
import ipaddress
import subprocess
import re
import urllib3

from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel

from templates.argus.modules.tls_cipher_suites import clean_domain_input
from argus.utils.util import resolve_to_ip, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
NBNS_REGEX = re.compile(r"\s*([^\s<]+)<([0-9A-Fa-f]{2})>\s+<(\w+)>\s+<ACTIVE>")

def banner():
    bar = "=" * 44
    console.print(f"[#2EC4B6]{bar}")
    console.print("[cyan]       Argus - NetBIOS Name Query")
    console.print(f"[#2EC4B6]{bar}\n")

def query_nbns(ip):
    start = time.time()
    try:
        proc = subprocess.Popen(
            ["nmblookup", "-A", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        out, _ = proc.communicate(timeout=DEFAULT_TIMEOUT)
    except:
        return [], None
    elapsed = int((time.time() - start) * 1000)
    names = []
    for line in out.splitlines():
        m = NBNS_REGEX.match(line)
        if m:
            names.append({
                "name": m.group(1),
                "code": m.group(2),
                "type": m.group(3),
                "time_ms": elapsed
            })
    return names, elapsed

def gather_hosts(target):
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        except:
            return []
    ip = resolve_to_ip(target)
    return [ip] if ip else []

def run(target, threads, opts):
    banner()
    hosts = gather_hosts(clean_domain_input(target)) if "/" in target else gather_hosts(target)
    if not hosts:
        console.print("[red]✖ No valid hosts to query[/red]")
        sys.exit(1)
    total = len(hosts)
    console.print(f"[*] Scanning {total} host(s)\n")

    results = {}
    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total}"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Querying NetBIOS…", total=total)
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(query_nbns, ip): ip for ip in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                names, tms = fut.result()
                results[ip] = names
                prog.advance(task)

    table = Table(title="NetBIOS Name Query Results", header_style="bold white", box=None)
    for col in ("IP","Name","Code","Type","Time(ms)"):
        table.add_column(col, overflow="fold")

    hosts_with = 0
    for ip, entries in results.items():
        if entries:
            hosts_with += 1
            for e in entries:
                table.add_row(ip, e["name"], e["code"], e["type"], str(e["time_ms"]))
        else:
            table.add_row(ip, "-", "-", "-", "-")

    console.print(table)
    summary = f"Hosts scanned: {total}  Hosts with names: {hosts_with}"
    console.print(Panel(summary, style="bold white"))
    console.print("[green][*] NetBIOS name query completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, target.replace("/", "_"))
        ensure_directory_exists(out)
        write_to_file(os.path.join(out, "nbns_results.txt"), table.__rich__() + f"\n{summary}")
        write_to_file(os.path.join(out, "nbns_results.json"), json.dumps(results, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ Usage: netbios_name_query.py <host|CIDR> [threads][/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8
    run(tgt, thr, {})
