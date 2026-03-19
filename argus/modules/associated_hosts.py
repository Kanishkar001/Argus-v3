#!/usr/bin/env python3
import sys, os, json, time

import requests, urllib3
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from tabulate import tabulate
from argus.utils.util import resolve_to_ip, clean_domain_input, ensure_directory_exists, write_to_file, check_api_configured
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, API_KEYS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console=Console(); TEAL="#2EC4B6"

def banner():
    border = "=" * 44
    console.print(f"[{TEAL}]{border}")
    console.print(f"[{TEAL}] Argus – Associated Hosts")
    console.print(f"[{TEAL}]{border}")
def _shodan(ip, timeout):
    key=API_KEYS.get("SHODAN_API_KEY")
    if not key: return []
    try:
        r=requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}", timeout=timeout, verify=False)
        if r.ok: return r.json().get("hostnames",[])
    except: return []
    return []

def _crtsh(ip, timeout):
    try:
        r=requests.get(f"https://crt.sh/?q={ip}&output=json", timeout=timeout)
        return list({j["common_name"] for j in r.json()})
    except: return []

def _passive_dns(ip, timeout):
    url=f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        r=requests.get(url, timeout=timeout)
        if "error" not in r.text.lower(): return r.text.splitlines()
    except: pass
    return []

def collect(ip, timeout, sources):
    hosts=set()
    with Progress(SpinnerColumn(),TextColumn("[cyan]Enumerating[/cyan]"),console=console,transient=True) as p:
        task=p.add_task("", total=len(sources))
        for src in sources:
            hosts.update(globals()[f"_{src}"](ip,timeout)); p.advance(task)
    return sorted(hosts)

def render(hosts): return tabulate([[h] for h in hosts],["Associated Host"],tablefmt="grid")

def export(dom, txt):
    if EXPORT_SETTINGS.get("enable_txt_export"):
        out=os.path.join(RESULTS_DIR,dom); ensure_directory_exists(out)
        write_to_file(os.path.join(out,"associated_hosts.txt"), txt)

def run(target,threads,opts):
    banner()
    dom=clean_domain_input(target)
    timeout=int(opts.get("timeout",DEFAULT_TIMEOUT))
    ip=resolve_to_ip(dom)
    if not ip: console.print("[red]DNS failure[/red]"); return
    srcs=opts.get("sources",["shodan","crtsh","passive_dns"])
    hosts=collect(ip,timeout,srcs)
    if not hosts: console.print("[yellow]No hosts found[/yellow]"); return
    txt=render(hosts); console.print(txt); console.print(f"[green]* {len(hosts)} host(s)[/green]")
    export(dom, txt)

if __name__=="__main__":
    tgt=sys.argv[1]; thr=int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 1
    opts={}
    if len(sys.argv)>3:
        try: opts=json.loads(sys.argv[3])
        except: pass
    run(tgt,thr,opts)
