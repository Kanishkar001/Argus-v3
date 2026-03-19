#!/usr/bin/env python3
import sys, os, json, asyncio, aiohttp, urllib.parse, bs4, collections
import requests
from rich.console import Console
from rich.table import Table
from argus.utils.util import ensure_url_format, clean_domain_input, validate_domain
from argus.config.settings import DEFAULT_TIMEOUT
console=Console()

opts=json.loads(sys.argv[3]) if len(sys.argv)>3 else{}
page_limit=int(opts.get("max_pages",100))
include_subdomains=bool(int(opts.get("include_subdomains",0)))

def banner():
    console.print("[bold green]=============================================[/bold green]")
    console.print("[bold green]        Argus – Content Discovery         [/bold green]")
    console.print("[bold green]=============================================[/bold green]")

def same_scope(root,u):
    if include_subdomains: return urllib.parse.urlparse(root).netloc.split(".")[-2:] == urllib.parse.urlparse(u).netloc.split(".")[-2:]
    return urllib.parse.urlparse(root).netloc == urllib.parse.urlparse(u).netloc

async def fetch(session,u):
    try:
        async with session.get(u,timeout=DEFAULT_TIMEOUT) as r:
            if r.status==200 and "text/html" in r.headers.get("content-type",""):
                return await r.text()
    except: pass
    return ""

def extract(u,html):
    soup=bs4.BeautifulSoup(html,"html.parser")
    links=set()
    assets_css=set(); assets_js=set()
    for tag in soup.find_all("a",href=True):
        links.add(urllib.parse.urljoin(u,tag["href"]))
    for l in soup.find_all("link",href=True):
        if l.get("rel")==["stylesheet"]: assets_css.add(urllib.parse.urljoin(u,l["href"]))
    for s in soup.find_all("script",src=True):
        assets_js.add(urllib.parse.urljoin(u,s["src"]))
    return links,assets_css,assets_js

async def crawl(start):
    q=collections.deque([start]); seen=set([start])
    internal=set(); external=set(); css=set(); js=set()
    async with aiohttp.ClientSession() as sess:
        while q and len(seen)<=page_limit:
            u=q.popleft()
            html=await fetch(sess,u)
            if not html: continue
            links,new_css,new_js=extract(u,html)
            css.update(new_css); js.update(new_js)
            for l in links:
                if l in seen: continue
                (internal if same_scope(start,l) else external).add(l)
                if same_scope(start,l) and len(seen)<page_limit:
                    seen.add(l); q.append(l)
    return internal,external,css,js

def show(base,robots,sitemaps,intl,ext,css,js):
    t=Table(title=f"Summary – {base}",show_header=True,header_style="bold magenta")
    t.add_column("Category",style="cyan"); t.add_column("Count",style="green")
    t.add_row("robots.txt","Yes" if robots else "No")
    t.add_row("Sitemap Links",str(len(sitemaps)))
    t.add_row("Internal Links",str(len(intl)))
    t.add_row("External Links",str(len(ext)))
    t.add_row("CSS",str(len(css))); t.add_row("JS",str(len(js)))
    console.print(t)

async def fetch_txt(url):
    try:
        r=requests.get(url,timeout=DEFAULT_TIMEOUT)
        return r.text if r.ok else ""
    except: return ""

async def main_async(target):
    banner()
    base=ensure_url_format(target)
    internal,external,css,js=await crawl(base)
    robots,sitemap=[],[]
    try:
        r=requests.get(f"{base}/robots.txt",timeout=DEFAULT_TIMEOUT)
        robots=r.text if r.ok else ""
        r=requests.get(f"{base}/sitemap.xml",timeout=DEFAULT_TIMEOUT)
        if r.ok:
            soup=bs4.BeautifulSoup(r.text,"xml")
            sitemap=[loc.text for loc in soup.find_all("loc")]
    except: pass
    show(base,robots,sitemap,internal,external,css,js)

def main(target):
    dom=clean_domain_input(target)
    if not validate_domain(dom):
        console.print("[red]Invalid domain[/red]"); return
    asyncio.run(main_async(target))

if __name__=="__main__":
    main(sys.argv[1])
