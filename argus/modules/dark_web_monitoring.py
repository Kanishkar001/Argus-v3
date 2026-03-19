#!/usr/bin/env python3
import sys, json, requests, concurrent.futures
from rich.console import Console
from rich.table import Table
console=Console()
opt=json.loads(sys.argv[3]) if len(sys.argv)>3 else{}
workers=int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else int(opt.get("workers",4))

def scylla(domain):
    try:
        r=requests.get(f"https://scylla.sh/search?q=email:*@{domain}&size=100",timeout=30,headers={'User-Agent':'Argus'})
        if r.ok: return ("Scylla",r.json())
    except: pass
    return ("Scylla",[])

def pastebin(domain):
    try:
        r=requests.get(f"https://psbdmp.ws/api/v3/search/{domain}",timeout=30)
        if r.ok: return ("Pastebin",r.json().get("data",[]))
    except: pass
    return ("Pastebin",[])

def display(label,data):
    if not data:
        console.print(f"[red]No data on {label}[/red]"); return
    if label=="Scylla":
        t=Table(title="Scylla",show_header=True,header_style="bold magenta")
        t.add_column("Email"); t.add_column("Password"); t.add_column("Source")
        for row in data: t.add_row(row.get("email",""),row.get("password",""),row.get("source",""))
        console.print(t)
    else:
        t=Table(title="Pastebin",show_header=True,header_style="bold magenta")
        t.add_column("ID"); t.add_column("Title"); t.add_column("Date")
        for row in data: t.add_row(str(row.get("id","")),row.get("title",""),row.get("date",""))
        console.print(t)

def main(target):
    banner="[bold green]=============================================[/bold green]\n[bold green]       Argus – Dark‑Web Monitor            [/bold green]\n[bold green]=============================================[/bold green]"
    console.print(banner)
    console.print(f"[*] Domain: {target}")
    funcs=[scylla,pastebin]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for label,data in pool.map(lambda f:f(target),funcs):
            display(label,data)
    console.print("[cyan][*] Monitoring done[/cyan]")

if __name__=="__main__":
    main(sys.argv[1])
