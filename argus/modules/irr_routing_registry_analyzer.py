import os
import sys
import socket
import requests
from rich.console import Console
from rich.table import Table
from colorama import init

from argus.utils.util import resolve_to_ip
from argus.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

def banner():
    console.print("""
    =============================================
    Argus - IRR / Routing Registry Analyzer
    =============================================
    """)

def get_asn(ip):
    try:
        r = requests.get(f"https://ip-api.com/json/{ip}?fields=as", timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            val = r.json().get("as")
            if val:
                return val.split()[0]
    except:
        pass
    return None

def radb_query(asn):
    out = []
    try:
        s = socket.create_connection(("whois.radb.net",43),timeout=DEFAULT_TIMEOUT)
        q = f"AS{asn}\n" if not asn.upper().startswith("AS") else f"{asn}\n"
        s.sendall(q.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        for block in data.decode(errors="ignore").split("\n\n"):
            route = None
            descr = None
            origin = None
            source = None
            for line in block.splitlines():
                if line.lower().startswith("route6:") or line.lower().startswith("route:"):
                    route = line.split(":",1)[1].strip()
                elif line.lower().startswith("descr:"):
                    descr = (descr+" " if descr else "") + line.split(":",1)[1].strip()
                elif line.lower().startswith("origin:"):
                    origin = line.split(":",1)[1].strip()
                elif line.lower().startswith("source:"):
                    source = line.split(":",1)[1].strip()
            if route:
                out.append((route,descr or "",origin or "",source or "RADB"))
    except:
        pass
    return out

def ripe_query(asn):
    try:
        q = asn if asn.upper().startswith("AS") else f"AS{asn}"
        r = requests.get(f"https://rest.db.ripe.net/search.json?query-string={q}&type-filter=route&type-filter=route6", timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            objs = r.json().get("objects",{}).get("object",[])
            out=[]
            for o in objs:
                attrs = {a["name"].lower():a["value"] for a in o.get("attributes",{}).get("attribute",[])}
                route = attrs.get("route") or attrs.get("route6")
                if route:
                    out.append((route,attrs.get("descr",""),attrs.get("origin",""),"RIPE"))
            return out
    except:
        pass
    return []

def display(asn, records):
    table = Table(title=f"IRR Routes for {asn}", show_header=True, header_style="bold magenta")
    table.add_column("Prefix", style="cyan")
    table.add_column("Descr", style="green", overflow="fold")
    table.add_column("Origin", style="yellow")
    table.add_column("Source", style="white")
    for r in records:
        table.add_row(r[0], r[1], r[2], r[3])
    console.print(table if records else "[yellow][!] No IRR route objects found[/yellow]")

if __name__ == "__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Pass a domain or IP.[/red]")
        sys.exit(1)
    target = sys.argv[1]
    console.print(f"[white][*] Resolving target for IRR analysis: {target}[/white]")
    ip = resolve_to_ip(target)
    if not ip:
        console.print("[red][!] Could not resolve target to IP[/red]")
        sys.exit(1)
    asn = get_asn(ip)
    if not asn:
        console.print("[red][!] Could not determine ASN[/red]")
        sys.exit(1)
    console.print(f"[white][*] ASN: {asn}[/white]")
    radb = radb_query(asn)
    ripe = ripe_query(asn)
    merged = {}
    for route,descr,origin,src in radb+ripe:
        merged[route]=(route,descr,origin,src)
    display(asn, list(merged.values()))
    console.print("[white][*] IRR routing registry analysis completed.[/white]")
