#!/usr/bin/env python3
import os, sys, json, ipaddress, requests, dns.resolver, urllib3
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, API_KEYS, RESULTS_DIR, EXPORT_SETTINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console(); TEAL="#2EC4B6"

DEFAULT_SHORT=7; DEFAULT_LONG=30

def banner():
    bar="="*44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]      Argus – IP Reputation Trending")
    console.print(f"[{TEAL}]{bar}")

def parse_opts(opts):
    s=int(opts.get("short_window",DEFAULT_SHORT))
    l=int(opts.get("long_window",DEFAULT_LONG))
    return (s,l) if l>=s else (s,s)

def resolve_domain(dom):
    ips=[]
    for rr in ("A","AAAA"):
        try: ips+= [r.address for r in dns.resolver.resolve(dom, rr, lifetime=DEFAULT_TIMEOUT)]
        except: pass
    return list(dict.fromkeys(ips))

def expand(t):
    if "/" in t and not any(c.isalpha() for c in t):
        try: return [str(h) for h in ipaddress.ip_network(t,strict=False).hosts()][:1024]
        except: return [t]
    return resolve_domain(clean_domain_input(t)) if any(c.isalpha() for c in t) else [t]

def abuse(ip,age):
    key=API_KEYS.get("ABUSEIPDB_API_KEY")
    if not key: return ("NA","NA")
    try:
        h={"Key":key,"Accept":"application/json"}
        r=requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays={age}",headers=h,timeout=DEFAULT_TIMEOUT,verify=False)
        if r.status_code==200:
            d=r.json()["data"]; return (str(d["abuseConfidenceScore"]), str(d["totalReports"]))
    except: pass
    return ("ERR","ERR")

def vt(ip):
    key=API_KEYS.get("VIRUSTOTAL_API_KEY")
    if not key: return ("NA","NA")
    try:
        r=requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",headers={"x-apikey":key},timeout=DEFAULT_TIMEOUT,verify=False)
        if r.status_code==200:
            a=r.json()["data"]["attributes"]; return (str(a["last_analysis_stats"]["malicious"]), str(a["reputation"]))
    except: pass
    return ("ERR","ERR")

def run(target, threads, opts):
    banner()
    short,long=parse_opts(opts)
    ips=expand(target)
    rows=[]
    with Progress(SpinnerColumn(),TextColumn("Querying…"),BarColumn(),console=console,transient=True) as pg:
        task=pg.add_task("",total=len(ips))
        for ip in ips:
            s_score,s_rep=abuse(ip,short)
            l_score,l_rep=abuse(ip,long)
            vt_mal,vt_rep=vt(ip)
            delta = str(int(s_score)-int(l_score)) if s_score.isdigit() and l_score.isdigit() else "-"
            rows.append((ip,s_score,l_score,delta,s_rep,l_rep,vt_mal,vt_rep)); pg.advance(task)

    tbl=Table(title="IP Reputation Trending",header_style="bold white")
    hdrs=("IP",f"AIPDB_{short}d",f"AIPDB_{long}d","Δ","Rpt_S","Rpt_L","VT_Mal","VT_Rep")
    for h in hdrs: tbl.add_column(h,style="cyan" if h=="IP" else "white")
    for r in rows: tbl.add_row(*r)
    console.print(tbl)
    console.print("[green]* Reputation trending completed[/green]")
    if EXPORT_SETTINGS["enable_txt_export"]:
        out=os.path.join(RESULTS_DIR,"ip_reputation"); ensure_directory_exists(out)
        write_to_file(os.path.join(out,f"{clean_domain_input(target)}.txt"), tbl.__rich__())

if __name__=="__main__":
    tgt=sys.argv[1]; thr=1; opts={}
    if len(sys.argv)>2:
        try: opts=json.loads(sys.argv[2])
        except: pass
    run(tgt,thr,opts)
