import os
import sys
import requests
import math
from datetime import datetime
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
     Argus - Network Timezone Detection
    =============================================
    """)

def fetch_ipapi(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,lat,lon,country,regionName,timezone,query", timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return {}

def fetch_worldtime(tz):
    try:
        r = requests.get(f"http://worldtimeapi.org/api/timezone/{tz}", timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return {}

def geo_distance(lat1, lon1, lat2, lon2):
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1))*math.cos(math.radians(lat2))*math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return 6371 * c

def display_results(ip, ipdata, timedata, local_offset_minutes):
    tz = ipdata.get("timezone", "N/A")
    country = ipdata.get("country", "N/A")
    region = ipdata.get("regionName", "N/A")
    lat = ipdata.get("lat")
    lon = ipdata.get("lon")
    remote_dt = timedata.get("datetime")
    remote_offset = timedata.get("utc_offset", "")
    if remote_dt:
        remote_dt = remote_dt.split(".")[0].replace("T", " ")
    local_offset = f"UTC{local_offset_minutes:+03d}:00" if isinstance(local_offset_minutes, int) else "N/A"
    distance = "N/A"
    try:
        if lat is not None and lon is not None and "LOCAL_LAT" in API_KEYS and "LOCAL_LON" in API_KEYS:
            distance = f"{geo_distance(float(API_KEYS['LOCAL_LAT']), float(API_KEYS['LOCAL_LON']), float(lat), float(lon)):.0f} km"
    except:
        pass
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green", overflow="fold")
    table.add_row("IP", ip)
    table.add_row("Timezone", tz)
    table.add_row("Remote Local Time", remote_dt or "N/A")
    table.add_row("Remote UTC Offset", remote_offset or "N/A")
    table.add_row("Your UTC Offset", local_offset)
    table.add_row("Country", country)
    table.add_row("Region", region)
    table.add_row("Latitude", str(lat) if lat is not None else "N/A")
    table.add_row("Longitude", str(lon) if lon is not None else "N/A")
    table.add_row("Approx Distance", distance)
    console.print(table)

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No target provided. Please pass a domain or IP.[/red]")
        sys.exit(1)
    target = sys.argv[1]
    console.print(f"[white][*] Resolving target for timezone detection: {target}[/white]")
    ip = resolve_to_ip(target)
    if not ip:
        console.print("[red][!] Could not resolve target to IP[/red]")
        sys.exit(1)
    local_offset_minutes = int(round((datetime.now().astimezone().utcoffset().total_seconds())/3600)) if datetime.now().astimezone().utcoffset() else None
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True)
    with progress:
        task = progress.add_task("Geo lookup", total=2)
        ipdata = fetch_ipapi(ip)
        progress.advance(task)
        timedata = fetch_worldtime(ipdata.get("timezone", "Etc/UTC")) if ipdata else {}
        progress.advance(task)
    display_results(ip, ipdata, timedata, local_offset_minutes)
    console.print("[white][*] Network timezone detection completed.[/white]")
