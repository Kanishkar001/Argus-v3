#!/usr/bin/env python3
import os
import sys
import json
import re
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
TEAL        = "#2EC4B6"
DEFAULT_MAX = 75
PAT_HREF    = re.compile(r'href=["\']([^"\']+)["\']', re.I)
PAT_SRC     = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
KEYWORDS    = (
    "eval(", "Function(", "atob(", "unescape(", r"\\x",
    "_0x", "fromCharCode", "CryptoJS"
)

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Argus – JavaScript Obfuscation Detector")
    console.print(f"[{TEAL}]{bar}\n")

def fetch_url(url, timeout):
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        return r.status_code, r.text
    except:
        return None, ""

def crawl(seed, max_pages, include_subs, timeout):
    parsed  = urlparse(seed)
    netloc  = parsed.netloc.lower()
    queue   = deque([seed])
    seen    = {seed}
    pages   = []

    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total} pages"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Crawling…", total=max_pages)
        while queue and len(pages) < max_pages:
            url = queue.popleft()
            _, text = fetch_url(url, timeout)
            pages.append((url, text))
            prog.advance(task)
            if not text:
                continue
            for m in PAT_HREF.finditer(text):
                link = urljoin(url, m.group(1))
                p = urlparse(link)
                if p.scheme in ("http","https"):
                    host = p.netloc.lower()
                    if (host == netloc or (include_subs and host.endswith("."+netloc))) and link not in seen:
                        seen.add(link)
                        queue.append(link)
    return pages

def extract_script_urls(pages, max_scripts):
    seen = set()
    for base, html in pages:
        for m in PAT_SRC.finditer(html):
            full = urljoin(base, m.group(1).strip())
            if full not in seen:
                seen.add(full)
                yield full
                if len(seen) >= max_scripts:
                    return

def score_script(txt):
    if not txt:
        return 0, "Empty"
    length      = len(txt)
    lines       = max(1, txt.count("\n"))
    avg_len     = length / lines
    nonalnum    = sum(1 for c in txt if not c.isalnum() and not c.isspace())
    pct_non     = nonalnum / length
    has_packed  = any(k in txt for k in KEYWORDS)
    has_hex     = bool(re.search(r"\\x[0-9A-Fa-f]{2}", txt))
    has_unicode = len(re.findall(r"\\u[0-9A-Fa-f]{4}", txt)) > 50
    score = 0
    score += 4 if has_packed else 0
    score += 2 if has_hex else 0
    score += 2 if has_unicode else 0
    score += 2 if pct_non > 0.4 else 0
    score += 1 if avg_len > 500 else 0
    score += 1 if length > 250_000 else 0

    if score >= 9:
        label = "Highly Obfuscated"
    elif score >= 6:
        label = "Obfuscated"
    elif score >= 3:
        label = "Minified"
    else:
        label = "Readable"
    return score, label

def run(target, threads, opts):
    banner()
    timeout      = int(opts.get("timeout",    DEFAULT_TIMEOUT))
    max_pages    = int(opts.get("max_pages",  50))
    max_scripts  = int(opts.get("max_scripts", DEFAULT_MAX))
    include_subs = bool(opts.get("include_subdomains", False))
    dom          = clean_domain_input(target)
    seed         = f"https://{dom}"

    pages   = crawl(seed, max_pages, include_subs, timeout)
    console.print(f"[white]* Crawled [cyan]{len(pages)}[/cyan] pages (include_subs={include_subs})[/white]\n")

    scripts = list(extract_script_urls(pages, max_scripts))
    console.print(f"[white]* Discovered [cyan]{len(scripts)}[/cyan] scripts (limit={max_scripts})[/white]\n")

    fetched = []
    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total} scripts"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Fetching scripts…", total=len(scripts))
        with ThreadPoolExecutor(max_workers=int(threads)) as pool:
            for txt in pool.map(lambda u: fetch_url(u, timeout)[1], scripts):
                fetched.append(txt)
                prog.advance(task)

    rows = []
    for url, txt in zip(scripts, fetched):
        sc, label = score_script(txt)
        rows.append((url, str(len(txt)), str(sc), label))

    table = Table(title=f"JS Obfuscation – {dom}", header_style="bold white")
    table.add_column("Script",     style="cyan",  overflow="fold")
    table.add_column("Bytes",      style="green", justify="right")
    table.add_column("Score",      style="yellow",justify="right")
    table.add_column("Assessment", style="white")

    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[green]* Obfuscation detection completed[/green]\n")

    if opts.get("export_txt", False) or EXPORT_SETTINGS.get("enable_txt_export", False):
        out_dir = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out_dir, "js_obfuscation.txt"), export_console.export_text())

if __name__=="__main__":
    tgt  = sys.argv[1]
    thr  = sys.argv[2]
    opts = json.loads(sys.argv[3]) if len(sys.argv)>3 else {}
    run(tgt, thr, opts)
