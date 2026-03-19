#!/usr/bin/env python3
import os
import sys
import json
import time
import requests
import urllib3
import concurrent.futures

from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from colorama import init

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()
TEAL = "#2EC4B6"

SECURITY_TXT_PATHS = ["/.well-known/security.txt", "/security.txt"]
PLATFORM_SIGS = {
    "HackerOne":     ["hackerone"],
    "Bugcrowd":      ["bugcrowd"],
    "Intigriti":     ["intigriti"],
    "YesWeHack":     ["yeswehack"],
    "OpenBugBounty":["openbugbounty"]
}
KEYWORDS = ("bug bounty", "security policy", "responsible disclosure", "vulnerability", "report security")

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Argus – Bug Bounty Program Finder")
    console.print(f"[{TEAL}]{bar}\n")

def fetch(path: str, base: str, timeout: int):
    url = base + path
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return url, r.status_code, r.text
    except:
        return url, 0, ""

def parse_security_txt(txt: str):
    data = {}
    for line in txt.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            data.setdefault(k.strip().lower(), []).append(v.strip())
    return data

def detect_platform(text: str):
    l = text.lower()
    for p, sigs in PLATFORM_SIGS.items():
        if any(s in l for s in sigs):
            return p
    return "-"

def scan(base: str, timeout: int, workers: int):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(fetch, p, base, timeout) for p in SECURITY_TXT_PATHS]
        for fut in concurrent.futures.as_completed(futures):
            url, status, txt = fut.result()
            if status == 200 and txt:
                data    = parse_security_txt(txt)
                contact = ",".join(data.get("contact", ["-"]))
                policy  = ",".join(data.get("policy",  ["-"]))
                plat    = detect_platform(txt)
                results.append((url, contact, policy, plat))
    return results

def run(target: str, threads: int, opts: dict):
    banner()
    start    = time.time()
    dom      = clean_domain_input(target)
    timeout  = int(opts.get("timeout", DEFAULT_TIMEOUT))
    workers  = int(opts.get("workers", threads or 4))
    base     = f"https://{dom}"

    console.print(f"[white]* Scanning {dom}  timeout={timeout}s  workers={workers}[/white]\n")
    rows = scan(base, timeout, workers)

    if not rows:
        try:
            r = requests.get(base, timeout=timeout, verify=False)
            html = r.text.lower()
            if any(k in html for k in KEYWORDS):
                plat = detect_platform(html)
                rows.append((base, "-", "-", plat))
        except:
            pass

    if rows:
        table = Table(
            title=f"Bug Bounty Finder – {dom}",
            header_style="bold magenta",
            box=box.MINIMAL
        )
        table.add_column("Source",    style="cyan", overflow="fold")
        table.add_column("Contact",   style="green", overflow="fold")
        table.add_column("PolicyURL", style="yellow", overflow="fold")
        table.add_column("Platform",  style="white")

        platforms = {}
        for src, contact, policy, plat in rows:
            table.add_row(src, contact, policy, plat)
            platforms[plat] = platforms.get(plat, 0) + 1

        console.print(table)
        summary = (
            f"Found {len(rows)} entries | " +
            ", ".join(f"{p}:{c}" for p, c in platforms.items() if p and p != "-") +
            f" | Elapsed: {time.time() - start:.2f}s"
        )
        console.print(summary)
    else:
        console.print("[yellow]No bug bounty or security.txt signals found[/yellow]")

    console.print(f"[green]* Completed in {time.time() - start:.2f}s[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        if rows:
            export_console.print(table)
            export_console.print(summary)
        write_to_file(
            os.path.join(out_dir, "bug_bounty_finder.txt"),
            export_console.export_text()
        )

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            opts = {}
    run(tgt, thr, opts)
