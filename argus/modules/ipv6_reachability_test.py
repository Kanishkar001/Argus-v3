#!/usr/bin/env python3
import sys, os, ipaddress, platform, socket, subprocess, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init, Fore, Style

from argus.utils.util import ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

init(autoreset=True)
console = Console()

def banner():
    console.print(f"{Fore.GREEN}{'='*44}")
    console.print(f"{Fore.GREEN}      Argus - IPv6 Enumerator")
    console.print(f"{Fore.GREEN}{'='*44}{Style.RESET_ALL}")

def ping6(ip, timeout):
    if platform.system() == "Windows":
        cmd = ["ping", "-6", "-n", "1", "-w", str(int(timeout*1000)), str(ip)]
    else:
        cmd = ["ping", "-6", "-c", "1", "-W", str(int(timeout)), str(ip)]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL).returncode == 0

def main():
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] Usage: ipv6_enumerator.py <IPv6_CIDR> [threads|options_json][/red]")
        sys.exit(1)

    cidr = sys.argv[1]
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except:
        console.print("[red][!] Invalid IPv6 CIDR[/red]")
        sys.exit(1)

    threads = 50
    timeout = DEFAULT_TIMEOUT
    max_hosts = 256
    opts = {}

    if len(sys.argv) > 2:
        arg = sys.argv[2]
        if arg.strip().startswith("{"):
            try: opts = json.loads(arg)
            except: opts = {}
        elif arg.isdigit():
            threads = int(arg)
    if len(sys.argv) > 3:
        try: opts.update(json.loads(sys.argv[3]))
        except: pass

    threads = opts.get("threads", threads)
    timeout = opts.get("timeout", timeout)
    max_hosts = opts.get("max_hosts", max_hosts)

    if network.prefixlen < 120:
        network = ipaddress.ip_network(f"{network.network_address}/120", strict=False)

    hosts = list(network.hosts())
    if len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]

    live = []
    console.print(f"[white][*] Probing {len(hosts)} addresses in {network}[/white]")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Probing…", total=len(hosts))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(ping6, ip, timeout): ip for ip in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                if fut.result():
                    live.append(ip)
                prog.update(task, description=str(ip), advance=1)

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("IPv6 Address", style="cyan")
    table.add_column("Reachable", style="green")
    table.add_column("PTR", style="yellow", overflow="fold")

    for ip in hosts:
        up = "Yes" if ip in live else "No"
        ptr = "-"
        if ip in live:
            try:
                ptr = socket.gethostbyaddr(str(ip))[0]
            except:
                ptr = "-"
        table.add_row(str(ip), up, ptr)

    console.print(table)
    console.print(f"[white][*] Enumeration completed: {len(live)} reachable[/white]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, str(network))
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out_dir, "ipv6_enumeration.txt"), export_console.export_text())

if __name__ == "__main__":
    main()
