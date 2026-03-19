#!/usr/bin/env python3
import os
import sys
import time
import ssl
import socket
import hashlib
import requests
import urllib3
import asyncio

from rich.console import Console
from rich.table import Table
from rich import box
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import asyncio.streams
asyncio.streams.StreamWriter.__del__ = lambda self: None

try:
    from argus.config.settings import HEADERS, DEFAULT_TIMEOUT
except ImportError:
    HEADERS = {}
    DEFAULT_TIMEOUT = 10

from argus.utils.util import clean_domain_input

console = Console()

def banner():
    console.print("""
==================================================
    Argus - HTTP/2 & HTTP/3 Support Checker
==================================================
""")

def resolve_host(host, timeout):
    start = time.time()
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({r[4][0] for r in infos})
        latency = int((time.time() - start) * 1000)
        return ips, latency
    except:
        return [], int((time.time() - start) * 1000)

def test_http2(host, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2","http/1.1"])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    tls = ctx.wrap_socket(sock, server_hostname=host)
    start = time.time()
    tls.connect((host,443))
    hs = int((time.time() - start) * 1000)
    alpn = tls.selected_alpn_protocol() or "-"
    tv = tls.version() or "-"
    cipher = tls.cipher()[0] if tls.cipher() else "-"
    cert = tls.getpeercert(True)
    der = ssl.DER_cert_to_PEM_cert(cert).encode()
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(der.decode())).hexdigest()[:12]
    peer = tls.getpeercert()
    subj = peer.get("subject",[])
    cn = next((v for r in subj for k,v in r if k=="commonName"),"-")
    issuer = peer.get("issuer",[])
    i_cn = next((v for r in issuer for k,v in r if k=="commonName"),"-")
    exp = peer.get("notAfter","-")
    tls.close()
    try: sock.close()
    except: pass
    try:
        r = requests.get(f"https://{host}/", headers=HEADERS, timeout=timeout, verify=False)
        status, size, srv = r.status_code, len(r.content), r.headers.get("server","-")
    except:
        status, size, srv = "-", "-", "-"
    return {
        "hs": hs, "alpn": alpn, "tls": tv, "cipher": cipher,
        "cn": cn, "issuer": i_cn, "expires": exp, "fp": fp,
        "status": status, "bytes": size, "server": srv
    }

async def _http3(host, timeout):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    start = time.time()
    client = await connect(host,443,configuration=cfg).__aenter__()
    await client.wait_connected()
    hs = int((time.time() - start) * 1000)
    try: await client.close()
    except: pass
    try: client._transport.close()
    except: pass
    return hs

def test_http3(host, timeout):
    try:
        hs = asyncio.run(_http3(host, timeout))
        return hs
    except:
        return None

def main(raw):
    banner()
    dom = clean_domain_input(raw)
    host = dom.split("://")[-1].split("/")[0]
    ips, dns_lat = resolve_host(host, DEFAULT_TIMEOUT)
    res2 = test_http2(host, DEFAULT_TIMEOUT)
    res3 = test_http3(host, DEFAULT_TIMEOUT)
    tbl = Table(
        title=f"Protocol Support – {dom}",
        box=box.ASCII, header_style="bold"
    )
    cols = [
        "Proto","DNS(ms)","IPs","HS(ms)","ALPN","TLSv",
        "Cipher","Cert CN","Issuer","Expires","SHA256","HTTP","Bytes","Server"
    ]
    for c in cols:
        tbl.add_column(c, overflow="fold", justify="right" if c.endswith("(ms)") or c in ("HTTP","Bytes") else "left")
    tbl.add_row(
        "HTTP/2",
        str(dns_lat),
        ",".join(ips) or "-",
        str(res2["hs"]),
        res2["alpn"],
        res2["tls"],
        res2["cipher"],
        res2["cn"],
        res2["issuer"],
        res2["expires"],
        res2["fp"],
        str(res2["status"]),
        str(res2["bytes"]),
        res2["server"]
    )
    tbl.add_row(
        "HTTP/3",
        str(dns_lat),
        ",".join(ips) or "-",
        str(res3 or "-"),
        "-","-","-","-","-","-","-","-","-","-"
    )
    console.print(tbl)
    summary = (
        f"DNS lat: {dns_lat}ms  HTTP/2 HS: {res2['hs']}ms  "
        f"HTTP/3 HS: {res3 or '-'}ms"
    )
    console.print(f"\nSummary: {summary}\n")

if __name__=="__main__":
    if len(sys.argv)<2:
        Console().print("[red]No target provided[/red]")
        sys.exit(1)
    try:
        main(sys.argv[1])
    except KeyboardInterrupt:
        Console().print("[red]Interrupted[/red]")
        sys.exit(0)
    except Exception as e:
        Console().print(f"[red]Error: {e}[/red]")
        sys.exit(1)
