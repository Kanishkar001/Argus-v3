#!/usr/bin/env python3
import os
import sys
import json
import re
import warnings
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

console = Console()

SERVICES = {
    "Jenkins":          ["/jenkins","/jenkins/login","/login?from=%2F"],
    "GitLab":           ["/users/sign_in","/gitlab","/-/signin"],
    "GitHub Enterprise":[ "/login","/user/login"],
    "Jira":             ["/jira","/secure/Dashboard.jspa","/login.jsp"],
    "Confluence":       ["/confluence","/wiki","/login.action"],
    "Grafana":          ["/grafana","/login/grafana","/dashboard/db"],
    "Kibana":           ["/kibana","/app/kibana","/login"],
    "Prometheus":       ["/prometheus","/graph","/alerts"],
    "Alertmanager":     ["/alertmanager","/alerts","/status"],
    "SonarQube":        ["/sonar","/sonarqube","/sessions/new"],
    "Harbor":           ["/harbor/sign-in","/harbor/projects","/api/v2.0/users"],
    "Portainer":        ["/portainer","/#/auth","/api/status"],
    "pgAdmin":          ["/pgadmin4","/pgadmin","/browser"],
    "MinIO":            ["/minio","/minio/login","/minio/admin"],
    "ElasticSearch":    [":9200/","9200/_cluster/health","9200/_nodes"]
}

SIGS = {
    "Jenkins":          "Jenkins",
    "GitLab":           "gitlab",
    "GitHub Enterprise":"github-enterprise|gh\\.enterprise",
    "Jira":             "Atlassian|JIRA",
    "Confluence":       "Confluence",
    "Grafana":          "grafana-app",
    "Kibana":           "kbn-version",
    "Prometheus":       "Prometheus Time Series Collection",
    "Alertmanager":     "Alertmanager|alertmanager",
    "SonarQube":        "SonarQube",
    "Harbor":           "Harbor",
    "Portainer":        "Portainer",
    "pgAdmin":          "pgAdmin",
    "MinIO":            "MinIO",
    "ElasticSearch":    "\"cluster_name\"|\"cluster_uuid\"|lucene_version"
}

UA = {"User-Agent":"ArgusCloudSvc/1.0"}

def banner():
    console.print("[cyan]" + "="*40)
    console.print("[cyan]   Argus – Cloud Service Enumeration")
    console.print("[cyan]" + "="*40)

def probe(svc, url):
    try:
        r = requests.get(url, headers=UA, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
        snippet = (r.text or "")[:2000] + " " + " ".join(f"{k}:{v}" for k,v in r.headers.items())
        matched = bool(re.search(SIGS.get(svc, ""), snippet, re.IGNORECASE))
        return svc, url, str(r.status_code), str(len(r.content or b"")), "Y" if matched else "N", r.headers.get("WWW-Authenticate", "-").split()[0]
    except:
        return svc, url, "ERR", "0", "N", "-"

def run(target, threads, opts):
    banner()
    dom = clean_domain_input(target)
    base = None
    for scheme in ("https","http"):
        try:
            resp = requests.get(f"{scheme}://{dom}", timeout=DEFAULT_TIMEOUT, verify=False)
            base = f"{scheme}://{urlparse(resp.url).netloc}"
            break
        except:
            continue
    if not base:
        console.print("[red]✖ Unable to reach domain[/red]")
        return

    endpoints = []
    for svc, paths in SERVICES.items():
        for p in paths:
            if p.startswith(":"):
                port = p[1:].split("/",1)[0]
                path = p[len(port)+2:]
                endpoints.append((svc, f"http://{dom}:{port}/{path}"))
            else:
                endpoints.append((svc, urljoin(base, p.lstrip("/"))))

    console.print(f"[white]* Enumerating [cyan]{len(endpoints)}[/cyan] service endpoints[/white]")
    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Probing services…", total=len(endpoints))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(probe, svc, url): (svc, url) for svc, url in endpoints}
            for fut in as_completed(futures):
                results.append(fut.result())
                prog.advance(task)

    table_str = tabulate(
        sorted(results, key=lambda r: (r[0], int(r[2]) if r[2].isdigit() else 999)),
        headers=["Service","URL","Status","Bytes","Sig","Auth"],
        tablefmt="grid"
    )
    console.print(table_str)
    console.print("[green]* Cloud service enumeration completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        write_to_file(os.path.join(out, "service_enum.txt"), table_str)

if __name__=="__main__":
    tgt = sys.argv[1] if len(sys.argv)>1 else ""
    thr = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 20
    opts = {}
    if len(sys.argv)>3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            pass
    run(tgt, thr, opts)
