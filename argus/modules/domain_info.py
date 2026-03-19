#!/usr/bin/env python3
import os
import sys
import json
import time
import socket
import dns.resolver
import requests
import urllib3

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file, resolve_to_ip
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()
resolver = dns.resolver.Resolver(configure=True)

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]        Argus – Domain Information")
    console.print(f"[cyan]{bar}\n")

def fetch_dns_records(domain, timeout):
    records = {}
    for rtype in ("A","AAAA","MX","NS","TXT","CAA","SOA"):
        try:
            answers = resolver.resolve(domain, rtype, lifetime=timeout)
            records[rtype] = [str(r).strip('"') for r in answers]
        except:
            records[rtype] = []
    return records

def fetch_ip_info(ip, timeout):
    url = f"https://ip-api.com/json/{ip}?fields=status,country,org,as,lat,lon"
    try:
        r = session.get(url, timeout=timeout, verify=False)
        data = r.json()
        if data.get("status") == "success":
            return (ip, data.get("country","-"), data.get("org","-"), data.get("as","-"), data.get("lat","-"), data.get("lon","-"))
    except:
        pass
    return (ip, "-", "-", "-", "-", "-")

def fetch_rdap(domain, timeout):
    url = f"https://rdap.org/domain/{domain}"
    try:
        r = session.get(url, timeout=timeout, verify=False)
        return r.json() if r.ok else {}
    except:
        return {}

def parse_rdap_network(data):
    net = data.get("network", {})
    return [
        ("Handle", net.get("handle","-")),
        ("Name",   net.get("name","-")),
        ("Type",   net.get("type","-")),
        ("Country",net.get("country","-")),
        ("Start",  net.get("startAddress","-")),
        ("End",    net.get("endAddress","-")),
    ]

def parse_rdap_entities(data):
    rows = []
    for ent in data.get("entities", []):
        roles = ",".join(ent.get("roles",[])) or "-"
        vcard = ent.get("vcardArray",[[],[]])[1]
        fn = next((i[3] for i in vcard if i[0]=="fn"), "-")
        emails = [i[3] for i in vcard if i[0]=="email"]
        rows.append((roles, fn, ",".join(emails) or "-"))
    return rows

def parse_rdap_events(data):
    return [(ev.get("eventAction","-"), ev.get("eventDate","-")) for ev in data.get("events",[])]

def run(target, threads, opts):
    banner()
    start = time.time()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    domain  = clean_domain_input(target)
    console.print(f"[white] [*] Gathering info for [cyan]{domain}[/cyan]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[white]DNS: {task.completed}/{task.total}"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Fetching DNS records", total=1)
        resolver.lifetime = timeout
        dns_records = fetch_dns_records(domain, timeout)
        prog.advance(task)

    ips = list({*dns_records["A"], *dns_records["AAAA"]})
    ip_info = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]GeoIP: {task.completed}/{task.total}"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog2:
        task2 = prog2.add_task("Resolving IP info", total=len(ips))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(fetch_ip_info, ip, timeout): ip for ip in ips}
            for fut in as_completed(futures):
                ip_info.append(fut.result())
                prog2.advance(task2)

    with Progress(
        SpinnerColumn(),
        TextColumn("[white]RDAP: {task.completed}/{task.total}"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog3:
        task3 = prog3.add_task("Querying RDAP", total=1)
        rdap_data = fetch_rdap(domain, timeout)
        prog3.advance(task3)

    whois_tbl = Table(title="WHOIS & DNS Records", header_style="bold magenta", box=box.MINIMAL)
    whois_tbl.add_column("Key", style="cyan")
    whois_tbl.add_column("Value", style="green", overflow="fold")
    for key, val in parse_rdap_network(rdap_data):
        whois_tbl.add_row(key, val)
    for rtype, vals in dns_records.items():
        whois_tbl.add_row(rtype, ",".join(vals) or "-")
    console.print(whois_tbl)

    if ip_info:
        ip_tbl = Table(title="IP Geolocation", header_style="bold magenta", box=box.MINIMAL)
        for col in ("IP","Country","Org","ASN","Lat","Lon"):
            ip_tbl.add_column(col, justify="center")
        for row in ip_info:
            ip_tbl.add_row(*map(str,row))
        console.print(ip_tbl)

    ents = parse_rdap_entities(rdap_data)
    if ents:
        ent_tbl = Table(title="RDAP Entities", header_style="bold magenta", box=box.MINIMAL)
        ent_tbl.add_column("Roles", style="cyan")
        ent_tbl.add_column("Name", style="green")
        ent_tbl.add_column("Email", style="yellow", overflow="fold")
        for r in ents:
            ent_tbl.add_row(*r)
        console.print(ent_tbl)

    evs = parse_rdap_events(rdap_data)
    if evs:
        ev_tbl = Table(title="RDAP Events", header_style="bold magenta", box=box.MINIMAL)
        ev_tbl.add_column("Action", style="cyan")
        ev_tbl.add_column("Date", style="green")
        for e in evs:
            ev_tbl.add_row(*e)
        console.print(ev_tbl)

    summary = (
        f"A records: {len(dns_records['A'])}  AAAA: {len(dns_records['AAAA'])}  "
        f"IPs geo: {len(ip_info)}  Entities: {len(ents)}  Events: {len(evs)}  "
        f"Elapsed: {time.time()-start:.2f}s"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] Domain information gathered[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(whois_tbl)
        if ip_info: export_console.print(ip_tbl)
        if ents:    export_console.print(ent_tbl)
        if evs:     export_console.print(ev_tbl)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "domain_info.txt"), export_console.export_text())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No domain provided.[/red]")
        sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(tgt, thr, opts)
