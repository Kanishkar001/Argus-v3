import os
import sys
import re
import json
import requests
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from argus.config.settings import DEFAULT_TIMEOUT
from argus.utils.util import clean_domain_input

init(autoreset=True)
console = Console()
requests.packages.urllib3.disable_warnings()

DEFAULT_MAX_PAGES = 100
DEFAULT_INCLUDE_SUBDOMAINS = False
COMMON_PATHS = ["/graphql","/api/graphql","/graphiql","/playground","/graph","/explorer"]

def banner():
    console.print("""
    =============================================
       Argus - GraphQL Introspection Probe
    =============================================
    """)

def parse_opts(argv):
    max_pages=DEFAULT_MAX_PAGES
    include_subs=DEFAULT_INCLUDE_SUBDOMAINS
    i=3
    while i < len(argv):
        a=argv[i]
        if a=="--max-pages" and i+1 < len(argv):
            try: max_pages=int(argv[i+1])
            except: pass
            i+=2; continue
        if a=="--include-subdomains" and i+1 < len(argv):
            include_subs = argv[i+1] not in ("0","false","False","no")
            i+=2; continue
        i+=1
    return max_pages, include_subs

def normalize_base(target):
    if "://" not in target:
        target="https://"+target
    return target.rstrip("/")+"/"

def same_domain(url,base_netloc,include_subs):
    n=urlparse(url).netloc.lower()
    if not n:
        return True
    if n==base_netloc:
        return True
    if include_subs and n.endswith("."+base_netloc):
        return True
    return False

def extract_links(html,base):
    out=[]
    for m in re.finditer(r'''(src|href)=["']([^"'#]+)''',html,re.I):
        out.append(urljoin(base,m.group(2)))
    return out

def crawl(base_url,max_pages,include_subs):
    base_netloc=urlparse(base_url).netloc.lower()
    seen=set(); q=[base_url]; urls=[]
    while q and len(urls)<max_pages:
        u=q.pop(0)
        if u in seen: continue
        seen.add(u)
        try:
            r=requests.get(u,timeout=DEFAULT_TIMEOUT,verify=False,allow_redirects=False)
        except:
            continue
        urls.append(u)
        ct=r.headers.get("Content-Type","")
        if "text/html" in ct:
            for l in extract_links(r.text,u):
                if same_domain(l,base_netloc,include_subs) and l not in seen:
                    q.append(l)
    return urls

def candidate_paths(base,urls):
    c=set(urljoin(base,p.lstrip("/")) for p in COMMON_PATHS)
    for u in urls:
        if "graphql" in u.lower() or "graphiql" in u.lower() or "playground" in u.lower():
            c.add(u)
    return sorted(c)

def gql_post(url,query,variables=None):
    data={"query":query}
    if variables is not None:
        data["variables"]=variables
    try:
        r=requests.post(url,json=data,timeout=DEFAULT_TIMEOUT,verify=False,allow_redirects=False,headers={"Content-Type":"application/json"})
        return r
    except:
        return None

def minimal_probe(url):
    r=gql_post(url,"query{__typename}")
    if not r:
        return False,None
    try:
        j=r.json()
    except:
        return False,None
    if "data" in j and "__typename" in j["data"]:
        return True,j
    if "errors" in j and any("__typename" in str(e) for e in j["errors"]):
        return True,j
    return False,j

def introspect(url):
    q="query Introspect{__schema{types{name kind fields{name} interfaces{name} possibleTypes{name}} queryType{name} mutationType{name} subscriptionType{name}}}"
    r=gql_post(url,q)
    if not r:
        return None
    try:
        return r.json()
    except:
        return None

def summarize_schema(j):
    if not j or "data" not in j or "__schema" not in j["data"]:
        return 0,0,0
    sch=j["data"]["__schema"]
    types=sch.get("types") or []
    tcnt=len(types)
    fcnt=0
    mcnt=0
    for t in types:
        fields=t.get("fields") or []
        fcnt+=len(fields)
    if sch.get("mutationType"):
        mcnt=1
    return tcnt,fcnt,mcnt

if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Please pass a domain or URL.[/red]")
        sys.exit(1)
    raw_target=sys.argv[1]
    threads=sys.argv[2] if len(sys.argv)>2 else "1"
    max_pages,include_subs=parse_opts(sys.argv)
    domain=clean_domain_input(raw_target)
    base=normalize_base(domain)
    console.print(f"[white][*] Crawling up to {max_pages} pages (include_subdomains={include_subs}).[/white]")
    urls=crawl(base,max_pages,include_subs)
    cands=candidate_paths(base,urls)
    rows=[]
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("Probing GraphQL",total=len(cands))
        for u in cands:
            ok,_=minimal_probe(u)
            intros=None
            tcnt=fcnt=mcnt=0
            if ok:
                intros=introspect(u)
                tcnt,fcnt,mcnt=summarize_schema(intros)
            rows.append((u,"Y" if ok else "N",str(tcnt),str(fcnt),str(mcnt)))
            progress.advance(task)
    table=Table(title=f"GraphQL Introspection Probe: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("Endpoint",style="cyan",overflow="fold")
    table.add_column("GraphQL?",style="green")
    table.add_column("Types",style="yellow")
    table.add_column("Fields",style="white")
    table.add_column("Mutation",style="blue")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] GraphQL introspection probing completed.[/white]")
