import os
import sys
import re
import socket
import subprocess
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init

from argus.utils.util import clean_domain_input, resolve_to_ip
from argus.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

def banner():
    console.print("""
    =============================================
           Argus - TTL Analysis
    =============================================
    """)

def dns_min_ttl(domain):
    ttl_vals = []
    try:
        for rtype in ["A","AAAA","MX","NS"]:
            try:
                ans = dns.resolver.resolve(domain, rtype, lifetime=DEFAULT_TIMEOUT)
                ttl_vals.append(ans.rrset.ttl)
            except:
                pass
    except:
        pass
    return min(ttl_vals) if ttl_vals else None

def icmp_ttl(ip):
    try:
        proc = subprocess.Popen(
            ["ping","-c","1","-W","1",ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        out,_ = proc.communicate(timeout=DEFAULT_TIMEOUT)
        m = re.search(r"ttl[=|:](\d+)", out, re.IGNORECASE)
        if m:
            return int(m.group(1))
    except:
        pass
    return None

def guess_start_ttl(observed):
    if observed is None:
        return None,"Unknown"
    bases = [32,60,64,128,255]
    nearest = min(bases, key=lambda b: abs(b-observed))
    fam = "Unix/Linux" if nearest in (60,64) else ("Windows" if nearest==128 else ("Network/Embedded" if nearest==255 else "Other"))
    return nearest,fam

def display(domain, ip, dns_ttl, icmp_val, guess_val, fam):
    table = Table(title=f"TTL Analysis: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Domain", domain)
    table.add_row("IP", ip)
    table.add_row("Min DNS TTL", str(dns_ttl) if dns_ttl is not None else "N/A")
    table.add_row("Observed ICMP TTL", str(icmp_val) if icmp_val is not None else "N/A")
    table.add_row("Guessed Start TTL", str(guess_val) if guess_val is not None else "N/A")
    table.add_row("Likely OS Family", fam)
    console.print(table)

if __name__ == "__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No domain provided.[/red]")
        sys.exit(1)
    domain = clean_domain_input(sys.argv[1])
    ip = resolve_to_ip(domain)
    if not ip:
        console.print("[red][!] Could not resolve domain.[/red]")
        sys.exit(1)
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True)
    with progress:
        t1 = progress.add_task("DNS TTL", total=1)
        dttl = dns_min_ttl(domain)
        progress.advance(t1)
        t2 = progress.add_task("ICMP TTL", total=1)
        ittl = icmp_ttl(ip)
        progress.advance(t2)
    gttl,fam = guess_start_ttl(ittl)
    display(domain, ip, dttl, ittl, gttl, fam)
    console.print("[white][*] TTL analysis completed.[/white]")
