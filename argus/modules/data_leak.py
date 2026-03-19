#!/usr/bin/env python3
import sys
import json
import argparse
import requests
import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from colorama import Fore, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - Advanced Data Leak Checker
    =============================================
    """)

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    p = urlparse(domain)
    return p.netloc or domain

def generate_emails(domain: str) -> list[str]:
    defaults = ["admin","contact","info","support","sales","webmaster","postmaster"]
    return [f"{u}@{domain}" for u in defaults]

def parse_breaches(html: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table")
    if not table:
        return []
    breaches = []
    for row in table.find_all("tr")[1:]:
        cols = [td.get_text(strip=True) for td in row.find_all("td")]
        if len(cols) >= 3:
            breaches.append({
                "Name": cols[0],
                "Date": cols[1],
                "DataClasses": cols[2].split(",")
            })
    return breaches

def check_email_breaches(email: str, session: requests.Session) -> tuple[str, list[dict] | None, str | None]:
    url = f"https://leak-lookup.com/search?query={email}"
    headers = {"User-Agent": "ArgusDataLeakChecker/1.0"}
    try:
        r = session.get(url, headers=headers, timeout=15, verify=False)
    except Exception as e:
        return email, None, f"Request error: {e}"
    if r.status_code != 200:
        return email, None, f"HTTP {r.status_code}"
    if "No leaks found" in r.text:
        return email, [], None
    return email, parse_breaches(r.text), None

def display_breaches(email: str, breaches, error: str | None):
    if error:
        console.print(Fore.RED + f"[!] {email}: {error}")
        return
    if not breaches:
        console.print(Fore.GREEN + f"[+] No breaches for {email}")
        return
    table = Table(title=f"Breaches for {email}", box=box.SIMPLE_HEAVY)
    table.add_column("Name", style="cyan")
    table.add_column("Date", style="white")
    table.add_column("Data Classes", style="yellow")
    for b in breaches:
        table.add_row(b["Name"], b["Date"], ",".join(b["DataClasses"]))
    console.print(table)

def main():
    banner()
    p = argparse.ArgumentParser("Argus – Advanced Data Leak Checker")
    p.add_argument("domain", help="Domain to check")
    p.add_argument("--email", action="append", help="Specific email(s) to check")
    p.add_argument("--threads", "-t", type=int, default=5, help="Number of concurrent threads")
    args = p.parse_args()

    domain = clean_domain_input(args.domain)
    emails = args.email if args.email else generate_emails(domain)
    console.print(Fore.WHITE + f"[*] Checking {len(emails)} address(es) on {domain} with {args.threads} threads\n")

    session = requests.Session()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as prog:
        task = prog.add_task("Starting…", total=len(emails))
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(check_email_breaches, e, session): e for e in emails}
            for fut in as_completed(futures):
                email, breaches, err = fut.result()
                prog.update(task, description=f"[cyan]Checking {email}", advance=1)
                display_breaches(email, breaches, err)

    console.print(Fore.CYAN + "\n[*] Data leak check completed")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Interrupted by user")
        sys.exit(1)
