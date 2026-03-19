import os
import sys
import socket
import ssl
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from argus.utils.util import clean_domain_input, resolve_to_ip
from argus.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

WORDLIST = [
    "www","app","api","admin","portal","login","dev","test","stage","staging",
    "prod","production","beta","dashboard","cpanel","mail","secure","internal",
    "intranet","vpn","cdn","assets","static","img","files","auth"
]

def banner():
    console.print("""
    =============================================
        Argus - Virtual Host Fuzzer
    =============================================
    """)

def base_scheme(domain):
    for scheme in ("https","http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
            return r.url
        except:
            pass
    return None

def fetch_with_host(ip, port, scheme, host):
    url = f"{scheme}://{ip}:{port}/"
    try:
        hdrs = {"Host": host}
        r = requests.get(url, headers=hdrs, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
        clen = r.headers.get("Content-Length")
        size = int(clen) if clen and clen.isdigit() else len(r.content)
        title = ""
        if b"<title" in r.content[:4096].lower():
            try:
                ct = r.content.decode(errors="ignore")
                import re
                m = re.search(r"<title[^>]*>(.*?)</title>", ct, re.I|re.S)
                if m:
                    title = m.group(1).strip()
            except:
                pass
        return (host, r.status_code, size, title)
    except:
        return (host, "ERR", 0, "")

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No domain provided.[/red]")
        sys.exit(1)
    domain = clean_domain_input(sys.argv[1])
    wl = WORDLIST
    if len(sys.argv) > 2 and os.path.isfile(sys.argv[2]):
        try:
            with open(sys.argv[2], "r", encoding="utf-8", errors="ignore") as f:
                wl = [l.strip() for l in f if l.strip()][:5000]
        except:
            pass
    base = base_scheme(domain)
    if not base:
        console.print("[red][!] Unable to reach domain.[/red]")
        sys.exit(1)
    scheme = urlparse(base).scheme
    ip = resolve_to_ip(domain)
    if not ip:
        console.print("[red][!] Could not resolve domain.[/red]")
        sys.exit(1)
    port = 443 if scheme == "https" else 80
    candidates = list(dict.fromkeys([f"{sub}.{domain}" for sub in wl]))
    console.print(f"[white][*] Fuzzing {len(candidates)} virtual hosts against {ip}:{port}[/white]")
    results = []
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True)
    with progress:
        task = progress.add_task("Fuzzing", total=len(candidates))
        with ThreadPoolExecutor(max_workers=50) as exe:
            futs = {exe.submit(fetch_with_host, ip, port, scheme, h): h for h in candidates}
            for f in as_completed(futs):
                results.append(f.result())
                progress.advance(task)
    baseline_host = domain
    baseline = [r for r in results if r[0] == baseline_host]
    base_len = baseline[0][2] if baseline else None
    hits = []
    for host, code, size, title in results:
        if host == baseline_host:
            continue
        if code == "ERR":
            continue
        if base_len is None or abs(size - base_len) > 100 or int(code) < 400:
            hits.append((host, str(code), str(size), title or "-"))
    table = Table(title=f"Virtual Host Findings: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Host", style="cyan", overflow="fold")
    table.add_column("Status", style="green")
    table.add_column("Size", style="yellow")
    table.add_column("Title", style="white", overflow="fold")
    for row in hits:
        table.add_row(*row)
    if hits:
        console.print(table)
    else:
        console.print("[yellow][!] No distinct virtual hosts discovered.[/yellow]")
    console.print("[white][*] Virtual host fuzzing completed.[/white]")
