#!/usr/bin/env python3
import os, sys, json, re, concurrent.futures, requests, urllib3
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console(); TEAL="#2EC4B6"

PAT_URL     = re.compile(r"https?://[^\s\"'<>]+", re.I)
PAT_EMAIL   = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I)
PAT_SECRET  = re.compile(
    r"(?:AWS|AKIA|ASIA)[A-Z0-9]{16,}|"
    r"AIza[0-9A-Za-z-_]{35}|"
    r"xox[baprs]-[0-9a-zA-Z]{10,48}|"
    r"sk_live_[0-9a-zA-Z]{24,}|"
    r"(?:api[_-]?key|secret|token|bearer)[\"'=\s:]{1,10}[A-Za-z0-9_\-]{8,}", re.I)

PAT_SCRIPT_SRC = re.compile(r"<script[^>]+src=['\"]([^'\"#]+)['\"]", re.I)

def banner():
    bar="="*44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]          Argus – JavaScript Analyzer")
    console.print(f"[{TEAL}]{bar}")

def fetch(url, timeout):
    try:
        r=requests.get(url, timeout=timeout, verify=False)
        ok = r.status_code==200 and ("javascript" in r.headers.get("Content-Type","") or url.lower().endswith(".js"))
        return url, (r.text if ok else "")
    except: return url, ""

def extract(base_html, base_url):
    return list(dict.fromkeys(urljoin(base_url, m.group(1).strip()) for m in PAT_SCRIPT_SRC.finditer(base_html)))[:150]

def analyse(text):
    return PAT_URL.findall(text), PAT_SECRET.findall(text), PAT_EMAIL.findall(text)

def run(target, threads, opts):
    banner()
    timeout=int(opts.get("timeout", DEFAULT_TIMEOUT))
    dom=clean_domain_input(target)
    base=f"https://{dom}"
    code, html = fetch(base, timeout)[1], fetch(base, timeout)[1]
    if not html:
        console.print("[red]✖ Unable to retrieve main page[/red]"); return
    scripts=extract(html, base)
    console.print(f"[white]* {len(scripts)} external <script> found[/white]")

    payloads=[(base,html)]
    if scripts:
        with Progress(SpinnerColumn(),TextColumn("Downloading…"),BarColumn(),console=console,transient=True) as pg:
            task=pg.add_task("",total=len(scripts))
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                for res in pool.map(lambda u: fetch(u,timeout), scripts):
                    payloads.append(res); pg.advance(task)

    findings=[]
    for _,txt in payloads:
        findings.append(analyse(txt))

    tot_urls=sum(len(f[0]) for f in findings)
    tot_secr=sum(len(f[1]) for f in findings)
    tot_mail=sum(len(f[2]) for f in findings)
    tbl=Table(title=f"JS Analyzer – {dom}", header_style="bold white")
    tbl.add_column("Scripts"); tbl.add_column("URLs"); tbl.add_column("Secrets"); tbl.add_column("Emails")
    tbl.add_row(str(len(scripts)), str(tot_urls), str(tot_secr), str(tot_mail))
    console.print(tbl)

    det=Table(title="Findings detail", header_style="bold white")
    det.add_column("Source",style="cyan",overflow="fold")
    det.add_column("Type",style="green")
    det.add_column("Value",style="yellow",overflow="fold")
    for (src,_), (urls,secr,mails) in zip(payloads,findings):
        for u in urls:  det.add_row(src,"URL",u)
        for s in secr:  det.add_row(src,"Secret",s)
        for e in mails: det.add_row(src,"Email",e)
    if tot_urls+tot_secr+tot_mail:
        console.print(det)
    console.print("[green]* JS analysis completed[/green]")

    if EXPORT_SETTINGS["enable_txt_export"]:
        out=os.path.join(RESULTS_DIR,dom); ensure_directory_exists(out)
        write_to_file(os.path.join(out,"js_analysis.txt"), det.__rich__() if det.row_count else tbl.__rich__())

if __name__=="__main__":
    tgt=sys.argv[1]; thr=int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 12
    opts={}
    if len(sys.argv)>3:
        try: opts=json.loads(sys.argv[3])
        except: pass
    run(tgt,thr,opts)
