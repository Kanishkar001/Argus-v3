#!/usr/bin/env python3
import os
import sys
import json
import time
import dns.resolver
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
resolver = dns.resolver.Resolver(configure=True)

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]         Argus - DNS Records Check")
    console.print(f"[cyan]{bar}\n")

def get_records(domain, rtype):
    try:
        answers = resolver.resolve(domain, rtype)
        return [str(r.to_text()) for r in answers]
    except:
        return ["-"]

def run(target, threads, opts):
    banner()
    start = time.time()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    types = tuple(map(str.upper, opts.get("types", "").split(","))) if opts.get("types") else ("A","AAAA","MX","NS","TXT","CNAME","SOA")
    domain = clean_domain_input(target)
    resolver.lifetime = timeout

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[rtype]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Querying records…", total=len(types), rtype="")
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(get_records, domain, r): r for r in types}
            for fut in as_completed(futures):
                rtype = futures[fut]
                recs = fut.result()
                results.append((rtype, recs))
                prog.update(task, advance=1, rtype=rtype)

    table = Table(title=f"DNS Records – {domain}", header_style="bold magenta", box=box.MINIMAL)
    table.add_column("Type", style="cyan")
    table.add_column("Value(s)", style="green", overflow="fold")
    total_values = 0
    for rtype, recs in results:
        vals = "; ".join(recs)
        total_values += 0 if recs == ["-"] else len(recs)
        table.add_row(rtype, vals)
    console.print(table)

    summary = (
        f"Types queried: {len(types)}  "
        f"Total records: {total_values}  "
        f"Elapsed: {time.time()-start:.2f}s"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] DNS records check completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "dns_records.txt"), export_console.export_text())

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(tgt, thr, opts)
