#!/usr/bin/env python3
import os, sys, json, dns.resolver, requests, urllib3, socket, concurrent.futures, time
from rich.console import Console
from rich.table import Table

from argus.utils.util import clean_domain_input, resolve_to_ip, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, API_KEYS, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

RBL_DOMS = ["dbl.spamhaus.org", "multi.uribl.com", "black.uribl.com", "rhsbl.scientificspam.net"]
IP_RBLS  = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]

def rbl_lookup(qname, zone, t):
    try:
        dns.resolver.resolve(f"{qname}.{zone}", "A", lifetime=t)
        return True
    except Exception:
        return False

def vt_lookup(dom, key, t):
    if not key:
        return {"score": "-", "malicious": None, "total": None}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{dom}", headers={"x-apikey": key}, timeout=t, verify=False)
        if r.status_code == 200:
            s = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"score": f"{s.get('malicious',0)}/{sum(s.values())}", "malicious": s.get("malicious",0), "total": sum(s.values())}
    except Exception:
        pass
    return {"score": "-", "malicious": None, "total": None}

def talos_lookup(dom, t):
    try:
        r = requests.get(f"https://talosintelligence.com/sb_api/query_lookup?query={dom}&query_type=domain", timeout=t, headers={"User-Agent": "Argus"}, verify=False)
        if r.status_code == 200:
            cat = r.json().get("category") or "-"
            return str(cat)
    except Exception:
        pass
    return "-"

def urlhaus_lookup(dom, t):
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": dom}, timeout=t, verify=False)
        j = r.json()
        if j.get("query_status") == "ok":
            urls = j.get("urls_count") or 0
            listed = j.get("host") == dom
            return {"listed": bool(listed and urls > 0), "count": int(urls)}
    except Exception:
        pass
    return {"listed": False, "count": 0}

def otx_lookup(dom, key, t):
    if not key:
        return {"pulses": None}
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{dom}/general", headers={"X-OTX-API-KEY": key}, timeout=t, verify=False)
        if r.status_code == 200:
            pulses = r.json().get("pulse_info", {}).get("count", 0)
            return {"pulses": int(pulses)}
    except Exception:
        pass
    return {"pulses": None}

def colorize(name, value):
    if name == "VirusTotal":
        if isinstance(value, str) and "/" in value:
            m, t = value.split("/", 1)
            try:
                m, t = int(m), int(t)
                pct = (m / max(t, 1)) * 100
                if m == 0: return "[bold green]0/{}[/]".format(t)
                if pct <= 5: return f"[green]{m}/{t}[/]"
                if pct <= 20: return f"[yellow]{m}/{t}[/]"
                return f"[bold red]{m}/{t}[/]"
            except Exception:
                return value
        return value
    if name in ("RBL Hits", "URLHaus", "OTX Pulses"):
        try:
            n = int(value.split()[0]) if isinstance(value, str) and value.split()[0].isdigit() else int(value)
            if n == 0: return "[bold green]0[/]"
            if n <= 2: return f"[yellow]{n}[/]"
            return f"[bold red]{n}[/]"
        except Exception:
            return value
    if name == "Cisco Talos":
        val = (value or "-").lower()
        if any(w in val for w in ["malicious", "phishing", "spam", "suspicious", "untrusted"]): return f"[bold red]{value}[/]"
        if any(w in val for w in ["unknown", "unrated", "uncategorized", "-"]): return f"[yellow]{value}[/]"
        return f"[green]{value}[/]"
    return value

def verdict(vt, rbl_count, talos, urlhaus_listed, otx_pulses):
    score = 0
    if isinstance(vt, dict) and vt.get("malicious") is not None and vt.get("total"):
        pct = (vt["malicious"] / max(vt["total"],1)) * 100
        if vt["malicious"] >= 5 or pct >= 10: score += 2
        elif vt["malicious"] >= 1: score += 1
    score += 2 if rbl_count >= 3 else (1 if rbl_count >= 1 else 0)
    tl = (talos or "").lower()
    if any(w in tl for w in ["malicious", "phishing", "spam", "suspicious", "untrusted"]): score += 2
    elif any(w in tl for w in ["unknown", "unrated", "uncategorized", "-"]): score += 0
    else: score += 0
    if urlhaus_listed: score += 2
    if isinstance(otx_pulses, int) and otx_pulses >= 3: score += 1
    if score >= 4: return "[bold red]High risk[/]"
    if score >= 2: return "[yellow]Medium risk[/]"
    return "[bold green]Low risk[/]"

def run(target, threads, opts):
    t = int(opts.get("timeout", DEFAULT_TIMEOUT))
    dom = clean_domain_input(target)
    ip = resolve_to_ip(dom) or "-"
    vt_key = opts.get("vt_key") or API_KEYS.get("VIRUSTOTAL_API_KEY", "")
    otx_key = opts.get("otx_key") or API_KEYS.get("OTX_API_KEY", "")

    vt = vt_lookup(dom, vt_key, t)
    talos = talos_lookup(dom, t)
    urlh = urlhaus_lookup(dom, t)
    otx = otx_lookup(dom, otx_key, t)

    rbl_hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(threads or 1))) as ex:
        futures = []
        for bl in RBL_DOMS:
            futures.append(ex.submit(rbl_lookup, dom, bl, t))
        if ip and ip != "-":
            try:
                socket.inet_aton(ip)
                rev = ".".join(reversed(ip.split(".")))
                for bl in IP_RBLS:
                    futures.append(ex.submit(rbl_lookup, rev, bl, t))
            except Exception:
                pass
        for idx, fut in enumerate(futures):
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                tag = (RBL_DOMS + IP_RBLS)[idx] if idx < len(RBL_DOMS + IP_RBLS) else "rbl"
                rbl_hits.append(tag)

    rbl_count = len(rbl_hits)
    vt_score = vt["score"]
    talos_val = talos
    urlhaus_val = f"{urlh['count']}" if urlh["listed"] else "0"
    otx_val = str(otx["pulses"]) if otx["pulses"] is not None else "-"

    table = Table(title=f"Reputation for {dom}", header_style="bold white")
    table.add_column("Engine")
    table.add_column("Result", overflow="fold")
    table.add_row("IP", ip)
    table.add_row("Verdict", verdict(vt, rbl_count, talos_val, urlh["listed"], otx["pulses"]))
    table.add_row("VirusTotal", colorize("VirusTotal", vt_score))
    table.add_row("Cisco Talos", colorize("Cisco Talos", talos_val))
    table.add_row("RBL Hits", colorize("RBL Hits", str(rbl_count)))
    if rbl_hits:
        table.add_row("RBL Lists", ", ".join(rbl_hits))
    table.add_row("URLHaus", colorize("URLHaus", urlhaus_val))
    table.add_row("OTX Pulses", colorize("OTX Pulses", otx_val))

    console.print(table)
    console.print("[green][*] Reputation check completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom); ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out, "domain_reputation.txt"), export_console.export_text())

    if EXPORT_SETTINGS.get("enable_json_export", False):
        out = os.path.join(RESULTS_DIR, dom); ensure_directory_exists(out)
        payload = {
            "domain": dom,
            "ip": ip,
            "verdict": verdict(vt, rbl_count, talos_val, urlh["listed"], otx["pulses"]),
            "virustotal": vt,
            "talos": talos_val,
            "rbl": {"count": rbl_count, "lists": rbl_hits},
            "urlhaus": urlh,
            "otx": otx,
            "timestamp": int(time.time()),
        }
        write_to_file(os.path.join(out, "domain_reputation.json"), json.dumps(payload, indent=2))
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]"); sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    try:
        opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except Exception:
        opts = {}
    run(tgt, thr, opts)
