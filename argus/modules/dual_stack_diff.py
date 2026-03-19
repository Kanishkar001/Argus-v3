#!/usr/bin/env python3
import os, sys, json, socket, ssl, hashlib, requests, urllib3, time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console(); TEAL = "#2EC4B6"

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]        Argus – IPv4 / IPv6 Dual-Stack Diff")
    console.print(f"[{TEAL}]{bar}\n")

def resolve_all(host, t):
    v4 = v6 = set()
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
            if fam == socket.AF_INET:  v4.add(sa[0])
            if fam == socket.AF_INET6: v6.add(sa[0])
    except:
        pass
    return list(v4), list(v6)

def fetch_https(dom, ip, fam, t):
    if not ip:
        return None
    addr = f"[{ip}]" if fam == 6 else ip
    url = f"https://{addr}/"
    hdr = {"Host": dom} if fam == 6 else {}
    try:
        t0 = time.time()
        r = requests.get(
            url, headers=hdr,
            timeout=t, verify=False, allow_redirects=False
        )
        r.elapsed_total = round((time.time() - t0) * 1000, 1)
        return r
    except:
        return None

def resp_summary(r):
    if not r:
        return ("ERR", "-", "-", "-", "-")
    code  = str(r.status_code)
    srv   = r.headers.get("Server", "-")
    ctype = r.headers.get("Content-Type", "-")
    clen  = r.headers.get("Content-Length", str(len(r.content)))
    hsh   = hashlib.sha256(r.content).hexdigest()[:12]
    return (code, srv, ctype, clen, hsh)

def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    dom     = clean_domain_input(target)

    console.print(f"[*] Resolving [cyan]{dom}[/cyan]\n")

    v4, v6 = resolve_all(dom, timeout)
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=console,
        transient=True
    ) as pg:
        t4 = pg.add_task("IPv4 request", total=1)
        r4 = fetch_https(dom, v4[0] if v4 else None, 4, timeout)
        pg.advance(t4)

        t6 = pg.add_task("IPv6 request", total=1)
        r6 = fetch_https(dom, v6[0] if v6 else None, 6, timeout)
        pg.advance(t6)

    sum4 = resp_summary(r4)
    sum6 = resp_summary(r6)

    table = Table(
        title=f"Dual-Stack Diff – {dom}",
        show_header=True,
        header_style="bold white"
    )
    for h in ("Family","IPs","HTTP","Server","Type","Bytes","SHA256-12","RTT-ms"):
        table.add_column(h, overflow="fold")
    table.add_row("IPv4", ", ".join(v4) or "-", *sum4, str(getattr(r4, "elapsed_total", "-")))
    table.add_row("IPv6", ", ".join(v6) or "-", *sum6, str(getattr(r6, "elapsed_total", "-")))
    console.print(table)

    console.print("[*] Dual-stack diff completed\n")

    if EXPORT_SETTINGS["enable_txt_export"]:
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        write_to_file(
            os.path.join(out, "dual_stack_diff.txt"),
            table.__rich__()
        )

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = 1
    opts = {}
    if len(sys.argv) > 2:
        try:
            opts = json.loads(sys.argv[2])
        except:
            pass
    run(tgt, thr, opts)
