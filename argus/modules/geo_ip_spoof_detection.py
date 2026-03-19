#!/usr/bin/env python3
import os
import sys
import json
import time
import requests
import urllib3
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from argus.utils.util import resolve_to_ip, clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS, API_KEYS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()

PROVIDERS = {
    "ip-api":  ("http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,as", None),
    "ipwhois": ("https://ipwho.is/{ip}", None),
    "ipinfo":  ("https://ipinfo.io/{ip}/json", API_KEYS.get("IPINFO_API_KEY"))
}

def banner():
    bar = "=" * 44
    console.print(f"[#2EC4B6]{bar}")
    console.print("[cyan]     Argus – Geo-IP Spoof Detection")
    console.print(f"[#2EC4B6]{bar}\n")

def query(name, tpl, ip, key, timeout):
    headers = {"User-Agent": "Argus"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    start = time.time()
    try:
        resp = session.get(tpl.format(ip=ip), headers=headers, timeout=timeout, verify=False)
        dt = int((time.time() - start) * 1000)
        if not resp.ok:
            return None
        j = resp.json()
        status = j.get("status") or j.get("success", True)
        if status in ("fail", False):
            return None
        country = j.get("country") or j.get("country_name", "-")
        region  = j.get("regionName") or j.get("region", "-")
        city    = j.get("city", "-")
        lat     = str(j.get("lat", "-"))
        lon     = str(j.get("lon", "-"))
        isp     = j.get("isp") or j.get("org") or "-"
        asn     = (j.get("as") or j.get("org") or "-").split()[0]
        return {
            "provider": name,
            "country": country,
            "region": region,
            "city": city,
            "lat": lat,
            "lon": lon,
            "isp": isp,
            "asn": asn,
            "time_ms": dt
        }
    except:
        return None

def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    dom     = clean_domain_input(target)
    ip      = resolve_to_ip(dom)
    if not ip:
        console.print("[red]✖ Could not resolve IP[/red]")
        return
    console.print(f"[*] Checking {ip} with {len(PROVIDERS)} providers\n")

    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total}"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Querying providers…", total=len(PROVIDERS))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(query, name, tpl, ip, key, timeout): name
                for name, (tpl, key) in PROVIDERS.items()
            }
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    results.append(res)
                prog.advance(task)

    table = Table(title=f"Geo-IP Spoof Check – {ip}", header_style="bold white", box=box.MINIMAL)
    for col in ("Provider","Country","Region","City","Lat","Lon","ISP","ASN","Time(ms)"):
        table.add_column(col, overflow="fold")
    for r in results:
        table.add_row(
            r["provider"],
            r["country"],
            r["region"],
            r["city"],
            r["lat"],
            r["lon"],
            r["isp"],
            r["asn"],
            str(r["time_ms"])
        )
    console.print(table if results else "[yellow]No valid provider responses[/yellow]")

    countries = {r["country"] for r in results}
    discrep = "Y" if len(countries) > 1 else "-"
    summary = f"Discrepancy detected? {discrep}"
    console.print(Panel(summary, style="yellow"))

    console.print("[green][*] Geo-IP spoof detection completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, ip)
        ensure_directory_exists(out)
        write_to_file(os.path.join(out, "geo_ip_spoof.txt"), table.__rich__() + f"\n{summary}")
        write_to_file(os.path.join(out, "geo_ip_spoof.json"), json.dumps(results, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else len(PROVIDERS)
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(tgt, thr, opts)
