#!/usr/bin/env python3
import os, sys, re, json, asyncio, aiohttp, urllib.parse, datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS, API_KEYS

console=Console()
RE_EMAIL=re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_API=re.compile(r"(api[_-]?key|token)['\"=: ]{0,6}[A-Za-z0-9\-_]{18,}",re.I)
RE_AWS=re.compile(r"AKIA[0-9A-Z]{16}")
RE_IP=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_JWT=re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

class Source:
    def __init__(s,n,search,get):s.n=n;s.s=search;s.g=get

async def psb_ses(session,q,p,to):
    u=f"https://psbdmp.ws/api/search/{urllib.parse.quote(q)}/{p}"
    try:
        async with session.get(u,timeout=to) as r:
            if r.status!=200:return[]
            d=await r.json(content_type=None)
            return[{"site":"PSBDMP","id":i["id"],"link":f"https://psbdmp.ws/{i['id']}"}for i in d]
    except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as e:
        console.print(f"[yellow][PSBDMP] Skipped (unreachable): {e}[/yellow]")
        return[]

async def psb_get(session,r,to):
    u=f"https://psbdmp.ws/api/paste/{r['id']}"
    try:
        async with session.get(u,timeout=to) as res:
            if res.status!=200:return""
            j=await res.json(content_type=None)
            return j.get("data","")
    except (aiohttp.ClientError, OSError, asyncio.TimeoutError):
        return""

GITHUB_TOKEN=API_KEYS.get("GITHUB_TOKEN","")

async def gh_search(session,q,p,to):
    hdr={"Accept":"application/vnd.github+json"}
    if GITHUB_TOKEN:hdr["Authorization"]=f"Bearer {GITHUB_TOKEN}"
    url=f"https://api.github.com/search/code?q={urllib.parse.quote(q)}+in:file&page={p}&per_page=100"
    try:
        async with session.get(url,headers=hdr,timeout=to) as r:
            if r.status!=200:return[]
            j=await r.json()
            out=[]
            for itm in j.get("items",[]):
                out.append({"site":"GitHub","id":itm["sha"],"link":itm["html_url"],"raw_url":itm["url"]})
            return out
    except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as e:
        console.print(f"[yellow][GitHub] Skipped (unreachable): {e}[/yellow]")
        return[]

async def gh_get(session,r,to):
    hdr={"Accept":"application/vnd.github+json"}
    if GITHUB_TOKEN:hdr["Authorization"]=f"Bearer {GITHUB_TOKEN}"
    try:
        async with session.get(r["raw_url"],headers=hdr,timeout=to) as res:
            if res.status!=200:return""
            j=await res.json()
            raw=j.get("download_url")
            if not raw:return""
            async with session.get(raw,timeout=to) as rr:
                return await rr.text()
    except (aiohttp.ClientError, OSError, asyncio.TimeoutError):
        return""

SOURCES=[Source("PSBDMP",psb_ses,psb_get),Source("GitHub",gh_search,gh_get)]

def hits(text):
    f={}
    for k,rx in[("Emails",RE_EMAIL),("API Keys",RE_API),("AWS Keys",RE_AWS),("IPv4",RE_IP),("JWTs",RE_JWT)]:
        m=rx.findall(text)
        if m:f[k]=list(dict.fromkeys(m))
    return f

def show(rows,q):
    t=Table(title=f"Pastes for '{q}'",header_style="bold magenta")
    t.add_column("Site",style="cyan")
    t.add_column("ID",style="yellow")
    t.add_column("Findings",style="green",overflow="fold")
    for r in rows:t.add_row(r["site"],r["id"],r["sum"])
    console.print(t)

async def main_async(q,thr,opt):
    to=aiohttp.ClientTimeout(total=opt["timeout"])
    mp=int(opt.get("max_pages",2))
    mx=int(opt.get("max_pastes",100))
    sem=asyncio.Semaphore(thr)
    async with aiohttp.ClientSession(timeout=to) as s:
        sch=[src.s(s,q,p,to)for src in SOURCES for p in range(1,mp+1)]
        results=await asyncio.gather(*sch,return_exceptions=True)
        lst=sum([r for r in results if isinstance(r,list)],[])[:mx]
        if not lst:
            console.print("[yellow]No pastes found[/yellow]")
            return
        rows=[]
        async def worker(r):
            async with sem:
                for src in SOURCES:
                    if r["site"]==src.n:
                        txt=await src.g(s,r,to)
                        break
                fd=hits(txt)
                if fd:
                    r["sum"]="; ".join(f"{k}:{len(v)}"for k,v in fd.items())
                    rows.append(r)
        await asyncio.gather(*(worker(r)for r in lst),return_exceptions=True)
        if rows:show(rows,q)
        else:console.print("[yellow]No matches[/yellow]")
        if EXPORT_SETTINGS.get("enable_txt_export"):
            d=os.path.join(RESULTS_DIR,clean_domain_input(q));ensure_directory_exists(d)
            ts=datetime.datetime.utcnow().isoformat()
            write_to_file(os.path.join(d,f"paste_monitor_{ts}.json"),json.dumps(rows,indent=2,ensure_ascii=False))

def main():
    if len(sys.argv)<3:
        console.print("error");sys.exit(1)
    q=sys.argv[1];thr=int(sys.argv[2]);opt=json.loads(sys.argv[3])if len(sys.argv)>3 else{}
    opt.setdefault("timeout",DEFAULT_TIMEOUT)
    asyncio.run(main_async(q,thr,opt))

if __name__=="__main__":
    main()