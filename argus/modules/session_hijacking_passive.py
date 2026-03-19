#!/usr/bin/env python3
import os
import sys
import json
import re
import requests
import urllib3
from http.cookies import SimpleCookie
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()

DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 8
DEFAULT_PATHS = ["/", "/login", "/signin", "/account", "/user", "/admin", "/api/", "/api/v1/"]
DEFAULT_HINTS = [
    "session","sess","sid","phpsessid","jsessionid","aspsessionid",
    "token","auth","jwt","bearer","sessionid"
]

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import EXPORT_SETTINGS, RESULTS_DIR


def reach(domain, timeout):
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            return r.url
        except:
            continue
    return None


def fetch(url, timeout):
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
        return r.status_code, r.headers
    except:
        return None, {}


def parse_cookies(set_cookie_header):
    cookies = []
    if not set_cookie_header:
        return cookies
    parts = set_cookie_header.split(",")
    buf = ""
    tmp = []
    for p in parts:
        if "=" in p.split(";", 1)[0] and buf:
            tmp.append(buf)
            buf = p
        else:
            buf = f"{buf},{p}" if buf else p
    if buf:
        tmp.append(buf)
    for raw in tmp:
        sc = SimpleCookie()
        sc.load(raw)
        for name, morsel in sc.items():
            attrs = {k.lower(): v for k, v in morsel.items()}
            cookies.append((name, morsel.value, attrs))
    return cookies


def assess_cookie(name, attrs, hints):
    lname = name.lower()
    sensitive = any(h in lname for h in hints)
    secure = "secure" in attrs
    http_only = "httponly" in attrs
    same_site = attrs.get("samesite", "-").lower()
    dom = attrs.get("domain", "-")
    path = attrs.get("path", "-")
    if sensitive and not (secure and http_only):
        risk = "High"
    elif sensitive and same_site not in ("strict", "lax"):
        risk = "Medium"
    else:
        risk = "Low"
    return sensitive, secure, http_only, same_site, dom, path, risk


def run(target, threads, opts):
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    paths = opts.get("paths", DEFAULT_PATHS)
    hints = opts.get("session_hints", DEFAULT_HINTS)

    domain = clean_domain_input(target)
    base = reach(domain, timeout)
    if not base:
        console.print(f"[red]✖ Unable to reach {domain}[/red]")
        return

    urls = [urljoin(base, p.lstrip("/")) for p in paths]
    console.print(f"[white]* Sampling {len(urls)} path(s) with {threads} thread(s), timeout={timeout}s[/white]")

    rows = []
    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total}"), BarColumn(), console=console) as prog:
        task = prog.add_task("Fetching…", total=len(urls))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(fetch, url, timeout): url for url in urls}
            for fut in as_completed(futures):
                url = futures[fut]
                code, hdrs = fut.result()
                sc = hdrs.get("Set-Cookie", "")
                for name, val, attrs in parse_cookies(sc):
                    sens, sec, httponly, ss, dom, path, risk = assess_cookie(name, attrs, hints)
                    rows.append((
                        url,
                        name,
                        "Y" if sens else "N",
                        "Y" if sec else "N",
                        "Y" if httponly else "N",
                        ss or "-",
                        dom or "-",
                        path or "-",
                        risk
                    ))
                prog.advance(task)

    table = Table(title=f"Session Cookie Security – {domain}", header_style="bold magenta")
    for col, style in [
        ("URL","cyan"),("Cookie","green"),("Sensitive","yellow"),
        ("Secure","white"),("HttpOnly","white"),("SameSite","blue"),
        ("Domain","magenta"),("Path","magenta"),("Risk","red")
    ]:
        table.add_column(col, style=style, overflow="fold")

    if rows:
        for r in rows:
            table.add_row(*map(str, r))
        console.print(table)
    else:
        console.print("[yellow](!) No Set-Cookie headers observed.[/yellow]")

    console.print("[green][*] Session hijacking passive analysis completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        write_to_file(os.path.join(out, "session_hijack_passive.txt"),
                      Console(record=True, width=console.width).export_text())


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_THREADS
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            pass
    run(tgt, thr, opts)
