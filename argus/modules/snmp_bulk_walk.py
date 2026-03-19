# modules/snmp_bulk_walk.py
import os
import sys
from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, nextCmd
from rich.console import Console
from rich.table import Table
from colorama import init

from argus.utils.util import resolve_to_ip
from argus.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

def banner():
    console.print("""
    =============================================
      Argus - SNMP Bulk Walk
    =============================================
    """)

def bulk_walk(ip, community):
    results = []
    for errInd, errStat, errIdx, varBinds in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, 161), timeout=1, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6')),
        lexicographicMode=False
    ):
        if errInd or errStat:
            break
        for oid, val in varBinds:
            results.append((str(oid), str(val)))
    return results

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No target provided. Please pass a domain or IP.[/red]")
        sys.exit(1)
    target = sys.argv[1]
    console.print(f"[white][*] Resolving target for SNMP walk: {target}[/white]")
    ip = resolve_to_ip(target)
    if not ip:
        console.print("[red][!] Could not resolve target to IP[/red]")
        sys.exit(1)
    try:
        from argus.config.settings import SNMP_COMMUNITY
    except:
        SNMP_COMMUNITY = "public"
    console.print(f"[white][*] Using SNMP community: {SNMP_COMMUNITY}[/white]")
    with console.status("[bold green]Performing SNMP bulk walk...[/bold green]", spinner="dots"):
        data = bulk_walk(ip, SNMP_COMMUNITY)
    if data:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("OID", style="cyan")
        table.add_column("Value", style="green")
        for oid, val in data:
            table.add_row(oid, val)
        console.print(table)
    else:
        console.print("[yellow][!] No SNMP data returned or access denied[/yellow]")
    console.print("[white][*] SNMP bulk walk completed.[/white]")
