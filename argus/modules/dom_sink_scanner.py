#!/usr/bin/env python3
import os
import random
import sys
import json
import re
import time
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()

JS_EXT_RE       = re.compile(r"\.js($|\?)", re.I)
SCRIPT_SRC_RE   = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.I)
INLINE_SCRIPT_RE= re.compile(r"<script[^>]*>(.*?)</script>", re.I|re.S)

SINK_PATTERNS = {
    "eval":             re.compile(r"\beval\s*\(", re.I),
    "innerHTML":        re.compile(r"\binnerHTML\s*=", re.I),
    "outerHTML":        re.compile(r"\bouterHTML\s*=", re.I),
    "document.write":   re.compile(r"\bdocument\.write\s*\(", re.I),
    "setTimeout":       re.compile(r"\bsetTimeout\s*\(", re.I),
    "setInterval":      re.compile(r"\bsetInterval\s*\(", re.I),
    "Function":         re.compile(r"\bnew\s+Function\s*\(", re.I),
    "location.assign":  re.compile(r"\blocation\.assign\s*\(", re.I),
    "location.replace": re.compile(r"\blocation\.replace\s*\(", re.I),
    "insertAdjacentHTML": re.compile(r"\binsertAdjacentHTML\s*\(", re.I),
}

def banner():
    border = "=" * 44
    console.print(f"[cyan]{border}")
    console.print("[cyan]     Argus – DOM Sink Scanner")
    console.print(f"[cyan]{border}\n")

def fetch_page(url, timeout):
    try:
        r = session.get(url, timeout=timeout, verify=False)
        return url, r.text
    except:
        return url, ""

def crawl(root, max_pages, timeout, workers):
    pages = []
    seen = {root}
    queue = [root]
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Crawling pages…", total=max_pages, url=root)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            while queue and len(pages) < max_pages:
                url = queue.pop(0)
                futures[pool.submit(fetch_page, url, timeout)] = url
                for fut in as_completed(list(futures)):
                    u, html = fut.result()
                    prog.update(task, advance=1, url=u)
                    pages.append((u, html))
                    del futures[fut]
                    for link in re.findall(r'href=["\']([^"\'#]+)', html):
                        full = urljoin(u, link)
                        if full.startswith(("http://","https://")) and urlparse(full).netloc == urlparse(root).netloc and full not in seen:
                            seen.add(full)
                            queue.append(full)
                    if len(pages) >= max_pages:
                        break
            for fut in as_completed(futures):
                u, html = fut.result()
                pages.append((u, html))
    return pages[:max_pages]

def extract_scripts(html, base_url):
    scripts = [urljoin(base_url, src) for src in SCRIPT_SRC_RE.findall(html)]
    inline = [m.group(1) for m in INLINE_SCRIPT_RE.finditer(html)]
    return scripts, inline

def fetch_script(url, timeout):
    try:
        r = session.get(url, timeout=timeout, verify=False)
        return r.text or ""
    except:
        return ""

def detect_sinks(code):
    hits = []
    for name, pat in SINK_PATTERNS.items():
        for i, line in enumerate(code.splitlines(), 1):
            if pat.search(line):
                snippet = line.strip()[:120]
                hits.append((name, i, snippet))
    return hits

def run(target, threads, opts):
    banner()
    start = time.time()
    timeout   = int(opts.get("timeout", DEFAULT_TIMEOUT))
    pages     = int(opts.get("max_pages", 75))
    sample_ratio = float(opts.get("sample_ratio", 0.3))
    domain    = clean_domain_input(target)
    root      = f"https://{domain}"

    html_pages = crawl(root, pages, timeout, threads)
    console.print(f"[white]* Crawled [green]{len(html_pages)}[/green] pages\n")

    scripts_to_fetch = []
    inline_codes = []
    for url, html in html_pages:
        s, inline = extract_scripts(html, url)
        scripts_to_fetch.extend(s)
        inline_codes.extend(inline)

    scripts_to_fetch = list(dict.fromkeys(scripts_to_fetch))
    sample_count = max(1, int(len(scripts_to_fetch) * sample_ratio))
    sampled = random.sample(scripts_to_fetch, sample_count)

    console.print(f"[white]* Fetching and scanning [green]{len(sampled)}[/green] external scripts\n")
    all_codes = inline_codes[:]
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Loading scripts…", total=len(sampled), url=sampled[0])
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(fetch_script, url, timeout): url for url in sampled}
            for fut in as_completed(futures):
                url = futures[fut]
                code = fut.result()
                prog.update(task, advance=1, url=url)
                all_codes.append(code)

    console.print(f"[white]* Detecting sinks in [green]{len(all_codes)}[/green] code blocks\n")
    results = []
    sink_counter = Counter()
    with Progress(
        SpinnerColumn(),
        TextColumn("Detecting…"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog2:
        task2 = prog2.add_task("", total=len(all_codes))
        for code in all_codes:
            hits = detect_sinks(code)
            for name, line, snippet in hits:
                results.append((name, line, snippet))
                sink_counter[name] += 1
            prog2.update(task2, advance=1)

    table = Table(title=f"DOM Sink Findings – {domain}", header_style="bold magenta", box=box.MINIMAL)
    table.add_column("Sink", style="cyan")
    table.add_column("Line", style="green")
    table.add_column("Snippet", style="yellow", overflow="fold")
    for name, line, snippet in results:
        table.add_row(name, str(line), snippet)
    console.print(table if results else "[green]No dangerous sinks detected[/green]")

    summary = (
        f"Pages: {len(html_pages)}  Scripts: {len(sampled)}  "
        f"Sinks: {len(results)}  Top sinks: "
        + ", ".join(f"{k}:{v}" for k,v in sink_counter.most_common(3))
        + f"  Elapsed: {time.time()-start:.2f}s"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] DOM sink scan completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        if results:
            export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "dom_sink_scan.txt"), export_console.export_text())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(tgt, thr, opts)
