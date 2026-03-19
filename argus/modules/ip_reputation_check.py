import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init

from argus.utils.util import resolve_to_ip
from argus.config.settings import DEFAULT_TIMEOUT, API_KEYS

init(autoreset=True)
console = Console()

def banner():
    console.print("""
    =============================================
         Argus - IP Reputation Check
    =============================================
    """)

def fetch_abuseipdb(ip):
    key = API_KEYS.get("ABUSEIPDB_API_KEY")
    if not key:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "score": d.get("abuseConfidenceScore"),
                "reports": d.get("totalReports"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "usage": d.get("usageType"),
                "source": "AbuseIPDB"
            }
    except:
        pass
    return None

def fetch_ipqualityscore(ip):
    key = API_KEYS.get("IPQUALITYSCORE_API_KEY")
    if not key:
        return None
    try:
        r = requests.get(
            f"https://ipqualityscore.com/api/json/ip/{key}/{ip}",
            timeout=DEFAULT_TIMEOUT
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "score": d.get("fraud_score"),
                "proxy": d.get("proxy"),
                "bot_status": d.get("bot_status"),
                "isp": d.get("ISP"),
                "country": d.get("country_code"),
                "source": "IPQualityScore"
            }
    except:
        pass
    return None

def fetch_otx(ip):
    try:
        r = requests.get(f"https://otx.alienvault.com/api/indicators/IPv4/{ip}/general", timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            pulse_count = r.json().get("pulse_info", {}).get("count")
            return {
                "score": None,
                "reports": pulse_count,
                "source": "AlienVault OTX"
            }
    except:
        pass
    return None

def display_results(ip, results):
    table = Table(title=f"IP Reputation: {ip}", show_header=True, header_style="bold magenta")
    table.add_column("Source", style="cyan")
    table.add_column("Score", style="green")
    table.add_column("Reports", style="yellow")
    table.add_column("Country", style="white")
    table.add_column("ISP/Usage", style="blue", overflow="fold")
    for r in results:
        table.add_row(
            r.get("source", "N/A"),
            str(r.get("score")) if r.get("score") is not None else "?",
            str(r.get("reports")) if r.get("reports") is not None else "?",
            r.get("country", "N/A"),
            (r.get("isp") or r.get("usage") or "")[:80]
        )
    console.print(table)

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No target provided. Please pass a domain or IP.[/red]")
        sys.exit(1)
    target = sys.argv[1]
    console.print(f"[white][*] Resolving target for IP reputation: {target}[/white]")
    ip = resolve_to_ip(target)
    if not ip:
        console.print("[red][!] Could not resolve target to IP[/red]")
        sys.exit(1)
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True)
    with progress:
        a = progress.add_task("AbuseIPDB", total=1)
        abuse = fetch_abuseipdb(ip)
        progress.advance(a)
        b = progress.add_task("IPQualityScore", total=1)
        ipq = fetch_ipqualityscore(ip)
        progress.advance(b)
        c = progress.add_task("AlienVault OTX", total=1)
        otx = fetch_otx(ip)
        progress.advance(c)
    results = [r for r in [abuse, ipq, otx] if r]
    if not results:
        console.print("[yellow][!] No reputation data available from configured sources[/yellow]")
    else:
        display_results(ip, results)
    console.print("[white][*] IP reputation check completed.[/white]")
