import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init

from argus.utils.util import clean_domain_input
from argus.config.settings import DEFAULT_TIMEOUT, API_KEYS

init(autoreset=True)
console = Console()

def banner():
    console.print("""
    =============================================
        Argus - Passive DNS History
    =============================================
    """)

def fetch_securitytrails(domain):
    key = API_KEYS.get("SECURITYTRAILS_API_KEY")
    if not key:
        return []
    try:
        r = requests.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": key},
            timeout=DEFAULT_TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            out = []
            for recset in data.get("records", []):
                values = recset.get("values", [])
                first_seen = recset.get("first_seen")
                last_seen = recset.get("last_seen")
                for v in values:
                    out.append((v.get("ip"), first_seen, last_seen, "SecurityTrails"))
            return out
    except:
        pass
    return []

def fetch_threatcrowd(domain):
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            ips = data.get("ips", [])
            out = []
            for ip in ips:
                out.append((ip, None, None, "ThreatCrowd"))
            return out
    except:
        pass
    return []

def fetch_hackertarget(domain):
    try:
        r = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200 and "error" not in r.text.lower():
            out = []
            for line in r.text.splitlines():
                if "A\t" in line:
                    try:
                        ip = line.split("\t")[-1].strip()
                        out.append((ip, None, None, "HackerTarget"))
                    except:
                        pass
            return out
    except:
        pass
    return []

def display_records(domain, records):
    table = Table(title=f"Passive DNS History: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("IP", style="cyan")
    table.add_column("First Seen", style="green")
    table.add_column("Last Seen", style="yellow")
    table.add_column("Source", style="white")
    for ip, first_seen, last_seen, src in records:
        table.add_row(ip or "N/A", str(first_seen) if first_seen else "?", str(last_seen) if last_seen else "?", src)
    console.print(table)

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No domain provided. Please pass a domain.[/red]")
        sys.exit(1)
    domain = clean_domain_input(sys.argv[1])
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True)
    with progress:
        progress.add_task("SecurityTrails", total=1)
        rec_st = fetch_securitytrails(domain)
        progress.advance(0)
        progress.add_task("ThreatCrowd", total=1)
        rec_tc = fetch_threatcrowd(domain)
        progress.advance(1)
        progress.add_task("HackerTarget", total=1)
        rec_ht = fetch_hackertarget(domain)
        progress.advance(2)
    merged = {}
    for ip, f, l, s in rec_st + rec_tc + rec_ht:
        rec = merged.get(ip, [ip, f, l, s])
        if not rec[1] and f:
            rec[1] = f
        if not rec[2] and l:
            rec[2] = l
        merged[ip] = rec
    records = [(ip, f, l, s) for ip, _, _, _ in merged.values() for f,l,s in [(merged[ip][1], merged[ip][2], merged[ip][3])]]
    display_records(domain, records)
    console.print("[white][*] Passive DNS history lookup completed.[/white]")
