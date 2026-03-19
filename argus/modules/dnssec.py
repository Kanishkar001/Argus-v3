#!/usr/bin/env python3
import os, sys, json, time, datetime, shutil
import dns.resolver, dns.exception, dns.rdatatype
import urllib3
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
CONSOLE_WIDTH = shutil.get_terminal_size().columns if shutil.get_terminal_size().columns > 0 else console.width
TEAL = "#2EC4B6"

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Argus – DNSSEC Checker")
    console.print(f"[{TEAL}]{bar}\n")

def make_table(title: str) -> Table:
    t = Table(title=title, title_style="bold magenta", show_header=True, header_style="bold white",
              box=box.HEAVY, expand=True, width=CONSOLE_WIDTH, pad_edge=True, show_lines=False, row_styles=["none","dim"])
    t.add_column("Zone",   justify="left",   style="cyan",   ratio=4, no_wrap=False)
    t.add_column("DNSKEY", justify="center", style="green",  ratio=2, no_wrap=True)
    t.add_column("DS",     justify="center", style="yellow", ratio=2, no_wrap=True)
    t.add_column("RRSIG",  justify="center", style="blue",   ratio=2, no_wrap=True)
    t.add_column("Status", justify="center", style="bold",   ratio=4, no_wrap=False)
    return t

def full_panel(text: str, title: str):
    console.print(Panel(text, title=title, border_style="white", box=box.HEAVY, expand=True, width=CONSOLE_WIDTH))

def style_status(text: str) -> str:
    s = {"Fully signed":"bold green","Signed (no DS)":"yellow","Delegation signed only":"yellow","Has keys only":"cyan","Not signed":"bold red"}
    st = s.get(text, "white")
    return f"[{st}]{text}[/{st}]"

def resolver_for(timeout: int) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.lifetime = timeout
    return r

def resolve(zone: str, rdtype: str, timeout: int):
    try:
        r = resolver_for(timeout)
        return list(r.resolve(zone, rdtype))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except (dns.exception.Timeout, Exception):
        return []

def query_count(domain: str, rdtype: str, timeout: int) -> int:
    try:
        r = resolver_for(timeout)
        return len(r.resolve(domain, rdtype))
    except:
        return 0

def parent_zone(name: str) -> str:
    p = name.split(".", 1)
    return p[1] if len(p) == 2 else ""

def algo_name(num: int) -> str:
    m = {1:"RSAMD5",3:"DSA",5:"RSASHA1",6:"DSA-NSEC3-SHA1",7:"RSASHA1-NSEC3-SHA1",8:"RSASHA256",
         10:"RSASHA512",12:"ECC-GOST",13:"ECDSAP256SHA256",14:"ECDSAP384SHA384",15:"ED25519",16:"ED448"}
    return m.get(int(num), str(num))

def ds_digest_name(num: int) -> str:
    m = {1:"SHA-1",2:"SHA-256",3:"GOST",4:"SHA-384"}
    return m.get(int(num), str(num))

def human_time(ts: int) -> str:
    try:
        dt = datetime.datetime.strptime(str(ts), "%Y%m%d%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(ts)

def sig_window_days(now: datetime.datetime, inception: int, expiration: int):
    try:
        inc = datetime.datetime.strptime(str(inception), "%Y%m%d%H%M%S")
        exp = datetime.datetime.strptime(str(expiration), "%Y%m%d%H%M%S")
        until = (exp - now).total_seconds() / 86400.0
        age = (now - inc).total_seconds() / 86400.0
        return round(max(until, 0.0), 2), round(max(age, 0.0), 2)
    except:
        return None, None

def run(target, threads, opts):
    banner()
    start = time.time()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    check_sub = bool(opts.get("check_subdomains", False))
    domain = clean_domain_input(target)
    zones = [domain] + ([f"www.{domain}"] if check_sub else [])
    rdtypes = ("DNSKEY", "DS", "RRSIG")
    total_tasks = len(zones) * len(rdtypes)
    counts = {z: {"DNSKEY": 0, "DS": 0, "RRSIG": 0} for z in zones}

    with Progress(SpinnerColumn(), TextColumn("[white]Checking: {task.fields[cur_zone]}[/white]", justify="right"),
                  BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("DNSSEC lookups…", total=total_tasks, cur_zone=zones[0])
        with ThreadPoolExecutor(max_workers=threads) as pool:
            fmap = {pool.submit(query_count, z, rd, timeout):(z, rd) for z in zones for rd in rdtypes}
            for fut in as_completed(fmap):
                z, rd = fmap[fut]
                try:
                    counts[z][rd] = fut.result()
                except:
                    counts[z][rd] = 0
                prog.update(task, advance=1, cur_zone=z)

    table = make_table(f"DNSSEC Check – {domain}")
    status_counter, details = {}, {}
    now = datetime.datetime.utcnow()

    for z in zones:
        dnskey, ds, rrsig = counts[z]["DNSKEY"], counts[z]["DS"], counts[z]["RRSIG"]
        if dnskey and ds and rrsig:
            status = "Fully signed"
        elif dnskey and rrsig and not ds:
            status = "Signed (no DS)"
        elif ds and rrsig and not dnskey:
            status = "Delegation signed only"
        elif dnskey and not (ds or rrsig):
            status = "Has keys only"
        else:
            status = "Not signed"
        status_counter[status] = status_counter.get(status, 0) + 1
        table.add_row(z, str(dnskey), str(ds), str(rrsig), style_status(status))

        d = {"zone": z, "status": status, "dnskey": [], "ds": [], "rrsig": [], "denial": {}}
        for r in resolve(z, "DNSKEY", timeout):
            try:
                d["dnskey"].append({"flags": int(r.flags), "sep": bool(int(r.flags) & 0x0100),
                                    "alg_num": int(r.algorithm), "algorithm": algo_name(int(r.algorithm)),
                                    "protocol": int(r.protocol)})
            except:
                pass
        for r in resolve(z, "DS", timeout):
            try:
                d["ds"].append({"key_tag": int(r.key_tag), "alg_num": int(r.algorithm),
                                "algorithm": algo_name(int(r.algorithm)),
                                "digest_type_num": int(r.digest_type),
                                "digest_type": ds_digest_name(int(r.digest_type))})
            except:
                pass
        for r in resolve(z, "RRSIG", timeout):
            try:
                if r.type_covered == dns.rdatatype.DNSKEY:
                    until, age = sig_window_days(now, int(r.inception), int(r.expiration))
                    d["rrsig"].append({"type_covered": "DNSKEY", "alg_num": int(r.algorithm),
                                       "algorithm": algo_name(int(r.algorithm)), "key_tag": int(r.key_tag),
                                       "inception": human_time(int(r.inception)),
                                       "expiration": human_time(int(r.expiration)),
                                       "age_days": age, "expires_in_days": until})
            except:
                pass
        d["denial"]["nsec"]  = len(resolve(z, "NSEC", timeout)) > 0
        d["denial"]["nsec3"] = len(resolve(z, "NSEC3", timeout)) > 0
        details[z] = d

    console.print(table)

    parent = parent_zone(domain)
    parent_ds = resolve(domain, "DS", timeout) if parent else []
    parent_note = "present" if parent_ds else "missing"
    full_panel(f"[bold]Parent DS[/bold]: {parent_note}   [bold]Parent[/bold]: {parent or '—'}", "Delegation")

    t_dnskey = make_table("DNSKEY Details")
    t_dnskey.add_column("Zone", style="cyan"); t_dnskey.add_column("Flags", justify="center")
    t_dnskey.add_column("SEP", justify="center"); t_dnskey.add_column("Algorithm", justify="center")
    t_dnskey.add_column("Protocol", justify="center")
    for z in zones:
        for k in details[z]["dnskey"]:
            t_dnskey.add_row(z, str(k["flags"]), "Yes" if k["sep"] else "No", f'{k["algorithm"]} ({k["alg_num"]})', str(k["protocol"]))
    if len(t_dnskey.rows): console.print(t_dnskey)

    t_ds = make_table("DS Records")
    t_ds.add_column("Zone", style="cyan"); t_ds.add_column("Key Tag", justify="center")
    t_ds.add_column("Algorithm", justify="center"); t_ds.add_column("Digest", justify="center")
    for z in zones:
        for r in details[z]["ds"]:
            t_ds.add_row(z, str(r["key_tag"]), f'{r["algorithm"]} ({r["alg_num"]})', f'{r["digest_type"]} ({r["digest_type_num"]})')
    if len(t_ds.rows): console.print(t_ds)

    t_sig = make_table("RRSIG (DNSKEY) Validity")
    t_sig.add_column("Zone", style="cyan"); t_sig.add_column("Alg", justify="center")
    t_sig.add_column("Key Tag", justify="center"); t_sig.add_column("Inception", justify="center")
    t_sig.add_column("Expiration", justify="center"); t_sig.add_column("Age (d)", justify="center")
    t_sig.add_column("Expires In (d)", justify="center")
    for z in zones:
        for srec in details[z]["rrsig"]:
            exp_in = srec["expires_in_days"]
            exp_style = "bold red" if exp_in is not None and exp_in <= 2 else ("yellow" if exp_in is not None and exp_in <= 7 else "green")
            t_sig.add_row(z, f'{srec["algorithm"]} ({srec["alg_num"]})', str(srec["key_tag"]),
                          srec["inception"], srec["expiration"],
                          str(srec["age_days"]) if srec["age_days"] is not None else "—",
                          f"[{exp_style}]{exp_in}[/]" if exp_in is not None else "—")
    if len(t_sig.rows): console.print(t_sig)

    t_den = make_table("Denial of Existence (NSEC/NSEC3)")
    t_den.add_column("Zone", style="cyan"); t_den.add_column("NSEC", justify="center")
    t_den.add_column("NSEC3", justify="center")
    for z in zones:
        n = details[z]["denial"]
        t_den.add_row(z, "[green]Yes[/green]" if n["nsec"] else "No", "[green]Yes[/green]" if n["nsec3"] else "No")
    if len(t_den.rows): console.print(t_den)

    parts = [f"[bold]{k}[/bold]: {v}" for k, v in status_counter.items()]
    parts.append(f"[bold]Parent DS[/bold]: {parent_note}")
    parts.append(f"[bold]Elapsed[/bold]: {time.time() - start:.2f}s")
    full_panel("   ".join(parts), "Summary")
    console.print("[green][*] DNSSEC check completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=CONSOLE_WIDTH)
        export_console.print(table)
        export_console.print(Panel(f"[bold]Parent DS[/bold]: {parent_note}   [bold]Parent[/bold]: {parent or '—'}", title="Delegation", border_style="white", box=box.HEAVY, expand=True, width=CONSOLE_WIDTH))
        if len(t_dnskey.rows): export_console.print(t_dnskey)
        if len(t_ds.rows): export_console.print(t_ds)
        if len(t_sig.rows): export_console.print(t_sig)
        if len(t_den.rows): export_console.print(t_den)
        export_console.print(Panel("   ".join(parts), title="Summary", border_style="white", box=box.HEAVY, expand=True, width=CONSOLE_WIDTH))
        write_to_file(os.path.join(out_dir, "dnssec.txt"), export_console.export_text())

    if EXPORT_SETTINGS.get("enable_json_export", False):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        payload = {"domain": domain, "parent": parent or None, "parent_ds_present": bool(parent_ds),
                   "summary": status_counter, "zones": details, "elapsed_sec": round(time.time()-start, 3)}
        write_to_file(os.path.join(out_dir, "dnssec.json"), json.dumps(payload, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]"); sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(tgt, thr, opts)
