import base64
import os
import sys
import socket
import subprocess
import ipaddress
import dns.resolver
from base64 import b64encode
from hashlib import md5, sha256
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init
try:
    import paramiko
except:
    paramiko=None

from argus.config.settings import DEFAULT_TIMEOUT
from argus.utils.util import clean_domain_input

init(autoreset=True)
console = Console()

DEFAULT_PORTS = [22]
DEFAULT_CONN_TIMEOUT = DEFAULT_TIMEOUT

def banner():
    console.print("""
    =============================================
      Argus - SSH Banner & Key Fingerprinter
    =============================================
    """)

def parse_ports(s):
    out=[]
    for p in s.split(","):
        p=p.strip()
        if not p: continue
        if "-" in p:
            a,b=p.split("-",1)
            try:
                a=int(a); b=int(b)
                for n in range(a,b+1): out.append(n)
            except:
                continue
        else:
            try: out.append(int(p))
            except: continue
    return sorted(set([p for p in out if 1<=p<=65535]))

def parse_opts(argv):
    ports=DEFAULT_PORTS
    i=3
    while i<len(argv):
        a=argv[i]
        if a=="--ports" and i+1<len(argv):
            ports=parse_ports(argv[i+1]) or DEFAULT_PORTS
            i+=2; continue
        i+=1
    return ports

def resolve_domain(domain):
    ips=[]
    try:
        a=dns.resolver.resolve(domain,"A",lifetime=DEFAULT_TIMEOUT)
        for r in a: ips.append(r.address)
    except:
        pass
    try:
        a6=dns.resolver.resolve(domain,"AAAA",lifetime=DEFAULT_TIMEOUT)
        for r in a6: ips.append(r.address)
    except:
        pass
    return list(dict.fromkeys(ips))

def expand_target(t):
    if "/" in t and not any(c.isalpha() for c in t):
        try:
            net=ipaddress.ip_network(t,strict=False)
            return [str(h) for h in net.hosts()]
        except:
            return [t]
    if any(c.isalpha() for c in t):
        d=clean_domain_input(t)
        return resolve_domain(d) or [t]
    return [t]

def grab_banner(ip,port):
    data=""
    s=None
    try:
        s=socket.create_connection((ip,port),timeout=DEFAULT_CONN_TIMEOUT)
        s.settimeout(DEFAULT_CONN_TIMEOUT)
        data=s.recv(512).decode(errors="ignore").strip()
    except:
        data=""
    finally:
        try:
            if s: s.close()
        except: pass
    return data

def paramiko_key(ip,port):
    if not paramiko:
        return None
    sock=None
    try:
        sock=socket.create_connection((ip,port),timeout=DEFAULT_CONN_TIMEOUT)
        trans=paramiko.transport.Transport(sock)
        trans.start_client(timeout=DEFAULT_CONN_TIMEOUT)
        key=trans.get_remote_server_key()
        trans.close()
        if key:
            m=md5(key.asbytes()).hexdigest()
            s=sha256(key.asbytes()).digest()
            s64=b64encode(s).decode()
            return key.get_name(),m,s64
    except:
        return None
    finally:
        try:
            if sock: sock.close()
        except: pass
    return None

def ssh_keyscan(ip,port):
    cmd=["ssh-keyscan","-T",str(int(DEFAULT_CONN_TIMEOUT)),"-p",str(port),ip]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=DEFAULT_TIMEOUT)
        if r.returncode==0 and r.stdout:
            line=r.stdout.strip().splitlines()[-1]
            parts=line.split()
            if len(parts)>=3:
                keytype=parts[1]
                b64=parts[2].encode()
                raw=base64.b64decode(b64) if "base64" in str(type(b64)) else None
                if raw:
                    return keytype,md5(raw).hexdigest(),b64encode(sha256(raw).digest()).decode()
    except:
        pass
    return None

def fingerprint(ip,port):
    b=grab_banner(ip,port)
    kt="-"; md="-"; sh="-"
    pk=paramiko_key(ip,port)
    if pk:
        kt,md,sh=pk
    else:
        ks=ssh_keyscan(ip,port)
        if ks:
            kt,md,sh=ks
    return b,kt,md,sh

if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Please pass a domain, IP, or CIDR.[/red]")
        sys.exit(1)
    raw=sys.argv[1]
    threads=sys.argv[2] if len(sys.argv)>2 else "1"
    ports=parse_opts(sys.argv)
    targets=expand_target(raw)
    rows=[]
    total=len(targets)*len(ports)
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("Probing SSH",total=total)
        for ip in targets:
            for port in ports:
                banner_txt,kt,md_fp,sh_fp=fingerprint(ip,port)
                rows.append((ip,str(port),banner_txt or "-",kt,md_fp,sh_fp))
                progress.advance(task)
    table=Table(title="SSH Banner & Key Fingerprinter",show_header=True,header_style="bold magenta")
    table.add_column("IP",style="cyan")
    table.add_column("Port",style="green")
    table.add_column("Banner",style="yellow",overflow="fold")
    table.add_column("KeyType",style="white")
    table.add_column("MD5",style="blue",overflow="fold")
    table.add_column("SHA256_b64",style="magenta",overflow="fold")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] SSH fingerprinting completed.[/white]")
