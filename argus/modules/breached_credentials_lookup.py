# modules/breached_credentials_lookup.py
import os, sys, json, hashlib, concurrent.futures, requests, urllib3
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, API_KEYS, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

def banner():
    console.print("[cyan]" + "="*44)
    console.print("[cyan]   Argus – Breached Credentials Lookup")
    console.print("[cyan]" + "="*44)

def pwned_password(pwd, t):
    sha = hashlib.sha1(pwd.encode()).hexdigest().upper()
    pref = sha[:5]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{pref}", timeout=t, verify=False)
        if r.ok:
            for line in r.text.splitlines():
                suf, cnt = line.split(":")
                if pref + suf == sha:
                    return int(cnt)
    except:
        pass
    return 0

def hibp_account(email, t):
    key = API_KEYS.get("HIBP_API_KEY", "")
    hdr = {"User-Agent": "Argus"}
    if key:
        hdr["hibp-api-key"] = key
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
                         headers=hdr, timeout=t, verify=False)
        if r.status_code == 404:
            return []
        if r.ok:
            return r.json()
    except:
        pass
    return None

def table_out(data, hdr):
    tbl = Table(show_header=True, header_style="bold white")
    for h in hdr:
        tbl.add_column(h, justify="left")
    for row in data:
        tbl.add_row(*[str(x) for x in row])
    console.print(tbl)

def run(target, threads, opts):
    banner()
    t = int(opts.get("timeout", DEFAULT_TIMEOUT))
    if target.startswith("password="):
        pwd = target.split("=", 1)[1]
        console.print(f"[white][*] Password exposure check")
        with Progress(SpinnerColumn(), TextColumn("PwnedPasswords…"), BarColumn(), console=console, transient=True) as p:
            task = p.add_task("", total=1)
            hits = pwned_password(pwd, t)
            p.advance(task)
        hdr, rows = ["Times Seen"], [[hits]]
    else:
        email = target
        console.print(f"[white][*] Breach lookup for: [cyan]{email}")
        with Progress(SpinnerColumn(), TextColumn("HIBP…"), BarColumn(), console=console, transient=True) as p:
            task = p.add_task("", total=1)
            breaches = hibp_account(email, t)
            p.advance(task)
        if breaches is None:
            console.print("[red][!] HIBP API unavailable")
            return
        hdr = ["Breach", "Domain", "Count", "Data"]
        rows = [[b.get("Name","-"),
                 b.get("Domain","-"),
                 str(b.get("PwnCount",0)),
                 ",".join(b.get("DataClasses",[]))] for b in breaches]
    table_out(rows, hdr)
    console.print("[green][*] Breached credentials lookup completed")
    if EXPORT_SETTINGS["enable_txt_export"]:
        out = os.path.join(RESULTS_DIR, clean_domain_input(target))
        ensure_directory_exists(out)
        write_to_file(os.path.join(out, "breached_credentials.txt"),
                      "\n".join("\t".join(map(str, r)) for r in rows))

if __name__ == "__main__":
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = {}
    if len(sys.argv) > 3:
        try: opts = json.loads(sys.argv[3])
        except: pass
    run(tgt, thr, opts)
