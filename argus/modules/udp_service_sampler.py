import os
import sys
import socket
import ipaddress
import dns.resolver
import random
import struct
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from argus.config.settings import DEFAULT_TIMEOUT
from argus.utils.util import clean_domain_input

init(autoreset=True)
console = Console()

DEFAULT_PORTS = [53,123,161,500,514,69]
DNS_QUERY_ID_MAX = 65535

def banner():
    console.print("""
    =============================================
          Argus - UDP Service Sampler
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
            except: continue
        else:
            try: out.append(int(p))
            except: continue
    return sorted(set([p for p in out if 1<=p<=65535]))

def parse_opts(argv):
    retries=1
    ports=DEFAULT_PORTS
    i=3
    while i<len(argv):
        a=argv[i]
        if a=="--ports" and i+1<len(argv):
            ports=parse_ports(argv[i+1]) or DEFAULT_PORTS
            i+=2; continue
        if a=="--retries" and i+1<len(argv):
            try: retries=int(argv[i+1])
            except: pass
            i+=2; continue
        i+=1
    return ports,retries

def resolve_domain(domain):
    ips=[]
    try:
        a=dns.resolver.resolve(domain,"A",lifetime=DEFAULT_TIMEOUT)
        for r in a: ips.append(r.address)
    except: pass
    try:
        a6=dns.resolver.resolve(domain,"AAAA",lifetime=DEFAULT_TIMEOUT)
        for r in a6: ips.append(r.address)
    except: pass
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

def build_dns_probe():
    tid=random.randint(0,DNS_QUERY_ID_MAX)
    header=struct.pack(">HHHHHH",tid,0x0100,1,0,0,0)
    qname=b"\x07argus01\x03net\x00"  # arbitrary
    qtype=1
    qclass=1
    tail=struct.pack(">HH",qtype,qclass)
    return header+qname+tail

def build_ntp_probe():
    return b'\x1b'+b'\x00'*47

def build_snmp_probe():
    return b'0\x1b\x02\x01\x01\x04\x06public\xa0\x0e\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x00'

def build_ike_probe():
    return os.urandom(28)

def build_syslog_probe():
    return b'<134>ArgusTest'

def build_tftp_probe():
    return b'\x00\x01test\x00octet\x00'

def classify_resp(port,data):
    if not data: return "-"
    l=len(data)
    if port==53 and l>=12: return "DNS"
    if port==123 and l>=48: return "NTP"
    if port==161: return "SNMP"
    if port==500 and l>=28: return "IKE"
    if port==514: return "Syslog"
    if port==69: return "TFTP"
    if l>0: return "RESP"
    return "-"

def udp_send(ip,port,payload,retries):
    fam=socket.AF_INET6 if ":" in ip else socket.AF_INET
    s=None
    data=None
    try:
        s=socket.socket(fam,socket.SOCK_DGRAM)
        s.settimeout(DEFAULT_TIMEOUT)
        for _ in range(max(1,retries)):
            try:
                s.sendto(payload,(ip,port))
                data,_=s.recvfrom(2048)
                break
            except socket.timeout:
                continue
    except:
        data=None
    finally:
        try:
            if s: s.close()
        except: pass
    return data

def payload_for_port(port):
    if port==53: return build_dns_probe()
    if port==123: return build_ntp_probe()
    if port==161: return build_snmp_probe()
    if port==500: return build_ike_probe()
    if port==514: return build_syslog_probe()
    if port==69:  return build_tftp_probe()
    return b'\x00'

if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Please pass a domain, IP, or CIDR.[/red]")
        sys.exit(1)
    raw=sys.argv[1]
    threads=sys.argv[2] if len(sys.argv)>2 else "1"
    ports,retries=parse_opts(sys.argv)
    targets=expand_target(raw)
    rows=[]
    total=len(targets)*len(ports)
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("Sampling UDP",total=total)
        for ip in targets:
            for port in ports:
                payload=payload_for_port(port)
                resp=udp_send(ip,port,payload,retries)
                svc=classify_resp(port,resp)
                size=str(len(resp)) if resp else "-"
                rows.append((ip,str(port),svc,size))
                progress.advance(task)
    table=Table(title="UDP Service Sampler",show_header=True,header_style="bold magenta")
    table.add_column("IP",style="cyan")
    table.add_column("Port",style="green")
    table.add_column("Service",style="yellow")
    table.add_column("Bytes",style="white")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] UDP service sampling completed.[/white]")
