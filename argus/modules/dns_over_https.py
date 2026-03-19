#!/usr/bin/env python3
import os
import sys
import json
import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box
from colorama import Fore, Style, init

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)
console = Console()
session = requests.Session()

DEFAULT_PROVIDERS = {
    "Cloudflare": "https://cloudflare-dns.com/dns-query",
    "Google":     "https://dns.google/resolve",
    "Quad9":      "https://dns.quad9.net:5053/dns-query",
    "AdGuard":    "https://dns.adguard.com/dns-query"
}

def banner():
    console.print(f"{Fore.GREEN}{'='*44}")
    console.print(f"{Fore.GREEN}        Argus - DoH Resolver Check")
    console.print(f"{Fore.GREEN}{'='*44}{Style.RESET_ALL}\n")

def query(url, domain, qtype, timeout):
    params = {"name": domain, "type": qtype}
    headers = {"Accept": "application/dns-json"}
    start = time.time()
    try:
        r = session.get(url, params=params, headers=headers, timeout=timeout, verify=False)
        latency = int((time.time() - start) * 1000)
        if r.ok:
            answers = [a.get("data") for a in r.json().get("Answer", []) if a.get("type") == (1 if qtype=="A" else 28)]
            return r.status_code, ",".join(answers) or "-", latency
        return r.status_code, "-", latency
    except requests.RequestException:
        return "ERR", "-", -1

def run(target, threads, opts):
    banner()
    start_all = time.time()
    timeout   = int(opts.get("timeout", DEFAULT_TIMEOUT))
    domain    = clean_domain_input(target)
    qtype     = opts.get("qtype", "A").upper()
    providers = opts.get("providers") or DEFAULT_PROVIDERS
    results   = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[provider]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Querying DoH", total=len(providers), provider="")
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(query, url, domain, qtype, timeout): name
                for name, url in providers.items()
            }
            for fut in as_completed(futures):
                name    = futures[fut]
                code, ips, lat = fut.result()
                results.append((name, code, ips, lat))
                prog.update(task, advance=1, provider=name)

    table = Table(
        title=f"DoH Resolver Results – {domain}",
        header_style="bold magenta",
        box=box.MINIMAL
    )
    table.add_column("Provider",    style="cyan")
    table.add_column("HTTP",        style="green", justify="right")
    table.add_column(f"{qtype} Records", style="yellow", overflow="fold")
    table.add_column("Latency(ms)", style="white", justify="right")

    latencies = []
    success = failure = 0
    for name, code, ips, lat in results:
        table.add_row(name, str(code), ips, str(lat))
        if code == 200 and lat >= 0:
            success += 1
            latencies.append(lat)
        else:
            failure += 1

    console.print(table)

    avg     = f"{sum(latencies)/len(latencies):.2f}" if latencies else "-"
    fastest = str(min(latencies)) if latencies else "-"
    slowest = str(max(latencies)) if latencies else "-"
    elapsed = f"{time.time() - start_all:.2f}s"

    summary = (
        f"Providers: {len(providers)}  Success: {success}  Failure: {failure}  "
        f"Avg: {avg}ms  Fastest: {fastest}ms  Slowest: {slowest}ms  Elapsed: {elapsed}"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] DoH resolver check completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out_dir, "dns_doh.txt"), export_console.export_text())

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(target, threads, opts)
