import os
import sys
import ssl
import socket
import json
import hashlib
import urllib.parse
import requests
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init
try:
    from OpenSSL import crypto
except:
    crypto = None
from argus.utils.util import clean_domain_input
from argus.config.settings import DEFAULT_TIMEOUT
init(autoreset=True)
console = Console()
def banner():
    console.print("""
    =============================================
       Argus - Rogue Certificate Check
    =============================================
    """)
def get_live_cert(domain, port=443):
    pem = None
    der = None
    cn = "-"
    sans = []
    issuer = "-"
    not_before = "-"
    not_after = "-"
    try:
        pem = ssl.get_server_certificate((domain, port))
        der = ssl.PEM_cert_to_DER_cert(pem)
        if crypto:
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
            subj = x509.get_subject()
            cn = getattr(subj, "CN", "-") or "-"
            sans = []
            try:
                ext_count = x509.get_extension_count()
                for i in range(ext_count):
                    e = x509.get_extension(i)
                    if e.get_short_name().decode().lower() == "subjectaltname":
                        data = str(e)
                        for part in data.split(","):
                            part = part.strip()
                            if part.lower().startswith("dns:"):
                                sans.append(part.split(":",1)[1])
            except:
                pass
            issuer_parts=[]
            iss = x509.get_issuer()
            for attr in ("CN","O","OU"):
                v = getattr(iss, attr, None)
                if v:
                    issuer_parts.append(v)
            issuer=",".join(issuer_parts) or "-"
            not_before = datetime.strptime(x509.get_notBefore().decode()[:14], "%Y%m%d%H%M%S").isoformat() if x509.get_notBefore() else "-"
            not_after = datetime.strptime(x509.get_notAfter().decode()[:14], "%Y%m%d%H%M%S").isoformat() if x509.get_notAfter() else "-"
        else:
            cn = domain
    except:
        pass
    fp_sha256 = hashlib.sha256(der).hexdigest() if der else "-"
    fp_sha1 = hashlib.sha1(der).hexdigest() if der else "-"
    return {
        "domain": domain,
        "cn": cn,
        "sans": sans,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "sha256": fp_sha256,
        "sha1": fp_sha1,
        "pem": pem or ""
    }
def fetch_ct(domain):
    q = urllib.parse.quote("%." + domain)
    url = f"https://crt.sh/?q={q}&output=json"
    out=[]
    try:
        r = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={"User-Agent":"ArgusRogueCert/1.0"})
        if r.status_code == 200:
            try:
                data = r.json()
            except:
                data = json.loads("[" + r.text.replace("}{","},{") + "]")
            for rec in data:
                name_value = rec.get("name_value","")
                common_name = rec.get("common_name","")
                issuer = rec.get("issuer_name","")
                nb = rec.get("not_before","")
                na = rec.get("not_after","")
                out.append((name_value,common_name,issuer,nb,na))
    except:
        pass
    return out
def classify_rogue(live_issuer, ct_issuer):
    if not ct_issuer:
        return "Unknown"
    if live_issuer == "-":
        return "Unknown"
    if live_issuer.lower() != ct_issuer.lower():
        return "Mismatch"
    return "Match"
def display(domain, live, ct_rows):
    table1 = Table(title=f"Live Certificate: {domain}", show_header=True, header_style="bold magenta")
    table1.add_column("Field", style="cyan")
    table1.add_column("Value", style="green", overflow="fold")
    table1.add_row("CN", live["cn"])
    table1.add_row("Issuer", live["issuer"])
    table1.add_row("Not Before", live["not_before"])
    table1.add_row("Not After", live["not_after"])
    table1.add_row("SHA256", live["sha256"])
    table1.add_row("SHA1", live["sha1"])
    table1.add_row("SANs", ",".join(live["sans"]) if live["sans"] else "-")
    console.print(table1)
    table2 = Table(title="CT Certificates", show_header=True, header_style="bold magenta")
    table2.add_column("DNS Name(s)", style="cyan", overflow="fold")
    table2.add_column("Common Name", style="green", overflow="fold")
    table2.add_column("Issuer", style="yellow", overflow="fold")
    table2.add_column("Not Before", style="white")
    table2.add_column("Not After", style="white")
    table2.add_column("Class", style="blue")
    for nv,cn,iss,nb,na in ct_rows:
        cls = classify_rogue(live["issuer"], iss)
        table2.add_row(nv.replace("\n",","), cn, iss, nb, na, cls)
    if ct_rows:
        console.print(table2)
    else:
        console.print("[yellow][!] No CT entries retrieved.[/yellow]")
def main(domain):
    banner()
    console.print(f"[white][*] Checking live certificate for: {domain}[/white]")
    live = get_live_cert(domain)
    console.print(f"[white][*] Querying CT logs for historical certificates[/white]")
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True)
    with progress:
        t = progress.add_task("crt.sh", total=1)
        ct_rows = fetch_ct(domain)
        progress.advance(t)
    display(domain, live, ct_rows)
    console.print("[white][*] Rogue certificate check completed.[/white]")
if __name__ == "__main__":
    if len(sys.argv)<2:
        banner()
        console.print("[red][!] No domain provided.[/red]")
        sys.exit(1)
    d = clean_domain_input(sys.argv[1])
    main(d)
