#!/usr/bin/env python3
import os
import sys
import json
import warnings
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

console = Console()
BASE_CANDIDATES = [
    "/login","/signin","/sign-in","/user/login","/account/login","/auth/login","/session/login",
    "/member/login","/dashboard/login","/admin/login","/cpanel","/wp-login.php","/login.html",
    "/login.php","/administrator","/auth","/account","/user","/portal","/signin.php","/sign-in.php"
]

def build_paths(opts):
    paths = list(BASE_CANDIDATES)
    for extra in opts.get("paths", []):
        if extra.startswith("/"):
            paths.append(extra)
    pf = opts.get("paths_file")
    if pf and os.path.isfile(pf):
        with open(pf, encoding="utf-8", errors="ignore") as f:
            for l in f:
                p = l.strip()
                if p.startswith("/"):
                    paths.append(p)
    return sorted(set(paths))

def derive_base(domain, timeout):
    for scheme in ("https://", "http://"):
        try:
            r = requests.get(scheme + domain, timeout=timeout, verify=False)
            return r.url.rstrip("/")
        except:
            pass
    return None

def fetch_page(args):
    url, timeout, follow = args
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=follow)
        return url, r.status_code, r.text if "html" in r.headers.get("Content-Type", "") else ""
    except:
        return url, None, ""

def parse_forms(html, base_url):
    out = []
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        method = form.get("method", "GET").upper()
        action = form.get("action") or base_url
        action = urljoin(base_url, action)
        inputs = form.find_all("input")
        buttons = form.find_all("button")
        user = passw = None
        tokens = []
        for inp in inputs:
            nm = inp.get("name", "")
            tp = inp.get("type", "").lower()
            if tp in ("password",) or "pwd" in nm.lower() or "pass" in nm.lower():
                passw = nm or passw
            if tp in ("text", "email") or any(k in nm.lower() for k in ("user","email","login")):
                user = nm or user
            if tp == "hidden" and any(k in nm.lower() for k in ("csrf","token","auth")):
                tokens.append(nm)
        if not passw:
            for btn in buttons:
                txt = btn.get_text(strip=True).lower()
                if "login" in txt or "sign in" in txt:
                    passw = passw or "-"
                    user = user or "-"
        if passw:
            out.append((method, action, user or "-", passw or "-", ",".join(tokens) or "-"))
    return out

def analyse(target, threads, opts):
    domain = clean_domain_input(target)
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    follow = bool(int(opts.get("follow_redirects", 1)))
    base = derive_base(domain, timeout)
    if not base:
        console.print("[red]✖ Unable to reach target[/red]")
        return
    paths = build_paths(opts)
    urls = [base] + [base + p for p in paths]
    total = len(urls)
    console.print(f"[*] Scanning {total} pages for login forms with {threads} threads\n")
    args = [(u, timeout, follow) for u in urls]
    pages = []
    with Progress(SpinnerColumn(), TextColumn("{task.fields[url]}", justify="right"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Fetching…", total=total, url="")
        with ThreadPoolExecutor(max_workers=threads) as pool:
            for url, status, html in pool.map(fetch_page, args):
                pages.append((url, status, html))
                prog.update(task, advance=1, url=urlparse(url).path or "/")
    findings = []
    for url, status, html in pages:
        if status and html:
            for form in parse_forms(html, url):
                findings.append((url, *form))
    if findings:
        table = Table(title=f"Login Forms – {domain}", header_style="bold magenta")
        for col, style in [("Page","cyan"),("Method","green"),("Action","yellow"),("User","white"),("Pass","white"),("Tokens","blue")]:
            table.add_column(col, style=style, overflow="fold")
        for row in findings:
            table.add_row(*row)
        console.print(table)
    else:
        console.print("[yellow]No login forms detected[/yellow]")
    summary = {
        "pages_scanned": total,
        "forms_found": len(findings),
        "unique_actions": len(set(f[2] for f in findings))
    }
    console.print(Panel(f"Pages: {summary['pages_scanned']}  Forms: {summary['forms_found']}  Actions: {summary['unique_actions']}",
                        title="Summary", style="bold white"))
    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        write_to_file(os.path.join(out, "login_forms.json"), json.dumps(findings, indent=2, ensure_ascii=False))

def main():
    if len(sys.argv) < 3:
        console.print("Error")
        return
    tgt = sys.argv[1]
    thr = int(sys.argv[2])
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    opts.setdefault("timeout", DEFAULT_TIMEOUT)
    opts.setdefault("follow_redirects", 1)
    analyse(tgt, thr, opts)

if __name__ == "__main__":
    main()
