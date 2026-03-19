import os
import sys
import re
import json
import requests
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from argus.config.settings import DEFAULT_TIMEOUT
from argus.utils.util import clean_domain_input

init(autoreset=True)
console = Console()
requests.packages.urllib3.disable_warnings()

PRODUCT_RX = re.compile(r"([A-Za-z0-9._-]+)[/ ]([0-9][A-Za-z0-9._-]*)")

def banner():
    console.print("""
    =============================================
          Argus - Passive CVE Mapper
    =============================================
    """)

def parse_opts(argv):
    prods=[]
    inv=None
    max_hits=20
    i=3
    while i<len(argv):
        a=argv[i]
        if a=="--products" and i+1<len(argv):
            for p in argv[i+1].split(","):
                p=p.strip()
                if ":" in p:
                    prods.append(tuple(p.split(":",1)))
            i+=2; continue
        if a=="--inventory" and i+1<len(argv):
            inv=argv[i+1]; i+=2; continue
        if a=="--max-hits" and i+1<len(argv):
            try: max_hits=int(argv[i+1])
            except: pass
            i+=2; continue
        i+=1
    return prods,inv,max_hits

def fetch_headers(url):
    try:
        r=requests.head(url,timeout=DEFAULT_TIMEOUT,verify=False,allow_redirects=True)
    except:
        try:
            r=requests.get(url,timeout=DEFAULT_TIMEOUT,verify=False,allow_redirects=True)
        except:
            return {}
    return r.headers

def derive_products_from_headers(hdrs):
    out=[]
    for k in ("Server","X-Powered-By","X-Generator"):
        v=hdrs.get(k)
        if not v: continue
        for m in PRODUCT_RX.finditer(v):
            out.append((m.group(1).lower(),m.group(2)))
    return out

def load_inventory(path):
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path,"r",encoding="utf-8",errors="ignore") as f:
            txt=f.read()
    except:
        return []
    prods=[]
    try:
        j=json.loads(txt)
        if isinstance(j,dict):
            for k,v in j.items():
                if isinstance(v,str):
                    prods.append((k.lower(),v))
                elif isinstance(v,dict):
                    ver=v.get("version") or "-"
                    prods.append((k.lower(),ver))
        elif isinstance(j,list):
            for x in j:
                if isinstance(x,dict):
                    n=x.get("name") or x.get("product")
                    v=x.get("version") or "-"
                    if n: prods.append((n.lower(),v))
    except:
        for l in txt.splitlines():
            l=l.strip()
            if not l: continue
            if ":" in l:
                a,b=l.split(":",1)
                prods.append((a.lower(),b))
    return prods

def uniq_products(lst):
    seen=set(); out=[]
    for n,v in lst:
        key=(n,v)
        if key in seen: continue
        seen.add(key); out.append((n,v))
    return out

def nvd_query(name,ver,max_hits):
    url=f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={name}%20{ver}&resultsPerPage={max_hits}"
    try:
        r=requests.get(url,timeout=DEFAULT_TIMEOUT,verify=False)
        if r.status_code==200:
            j=r.json()
            vulns=j.get("vulnerabilities",[])
            cnt=len(vulns)
            sev="-"
            mx=0.0
            for v in vulns:
                m=v.get("cve",{}).get("metrics",{})
                for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                    if key in m:
                        for entry in m[key]:
                            b=entry.get("cvssData",{}).get("baseScore")
                            if b is not None and float(b)>mx:
                                mx=float(b); sev=str(b)
            return ("Y" if cnt else "-",str(cnt),sev if cnt else "-")
        return ("ERR","-","HTTP"+str(r.status_code))
    except:
        return ("ERR","-","-")

if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Please pass a domain or URL.[/red]")
        sys.exit(1)
    raw=sys.argv[1]
    threads=sys.argv[2] if len(sys.argv)>2 else "1"
    prods_cli,inv_path,max_hits=parse_opts(sys.argv)
    domain=clean_domain_input(raw)
    base="https://"+domain if "://" not in domain else domain
    hdrs=fetch_headers(base)
    prods_hdr=derive_products_from_headers(hdrs)
    prods_inv=load_inventory(inv_path)
    prods=uniq_products(prods_cli+prods_hdr+prods_inv)
    if not prods:
        console.print("[yellow][!] No product/version hints discovered.[/yellow]")
        prods=[("unknown","-")]
    rows=[]
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("Querying NVD",total=len(prods))
        for n,v in prods:
            st,cnt,sev=nvd_query(n,v,max_hits)
            rows.append((n,v,st,cnt,sev))
            progress.advance(task)
    table=Table(title=f"Passive CVE Mapper: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("Product",style="cyan")
    table.add_column("Version",style="green")
    table.add_column("Vulns?",style="yellow")
    table.add_column("CVE#","white")
    table.add_column("MaxScore",style="magenta")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] Passive CVE mapping completed.[/white]")
