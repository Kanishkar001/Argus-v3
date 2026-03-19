"""
argus.modules.nuclei_lite
~~~~~~~~~~~~~~~~~~~~~~~~~~
Lightweight CVE and misconfiguration scanner.
No external binaries needed — uses HTTP probes and response pattern
matching to detect common vulnerabilities, exposed admin panels,
default credentials pages, and known CVE fingerprints.

Covers: exposed panels, default pages, path traversal, SSRF probes,
        header injections, common CVE signatures, info disclosures.
"""
from __future__ import annotations

import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import requests
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.modules.base import ArgusModule
from argus.utils.util import ensure_url_format, clean_domain_input

console = Console()

# ─── Probe definitions ────────────────────────────────────────────────────────
@dataclass
class Probe:
    id:          str
    name:        str
    severity:    str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    path:        str
    method:      str = "GET"
    body:        str = ""
    headers:     dict = field(default_factory=dict)
    # Matchers: all must pass
    status:      list[int] = field(default_factory=list)   # empty = any
    contains:    list[str] = field(default_factory=list)   # body contains ALL
    not_contains:list[str] = field(default_factory=list)   # body must NOT contain
    regex:       str = ""                                   # body matches regex
    header_key:  str = ""                                   # response header must exist
    description: str = ""


PROBES: list[Probe] = [
    # ── Exposed admin / management panels ─────────────────────────────────
    Probe("exposed-phpinfo", "PHP Info Page Exposed", "HIGH",
          "/phpinfo.php", status=[200],
          contains=["PHP Version", "php.ini"],
          description="phpinfo() exposes config, paths, env vars"),

    Probe("exposed-adminer", "Adminer DB Panel", "CRITICAL",
          "/adminer.php", status=[200],
          contains=["adminer", "Login"],
          description="Database admin panel publicly accessible"),

    Probe("exposed-phpmyadmin", "phpMyAdmin Exposed", "CRITICAL",
          "/phpmyadmin/", status=[200],
          contains=["phpMyAdmin", "pma_"],
          description="Database admin panel publicly accessible"),

    Probe("exposed-wp-login", "WordPress Login Page", "INFO",
          "/wp-login.php", status=[200],
          contains=["user_login", "WordPress"],
          description="WordPress login panel reachable"),

    Probe("exposed-jenkins", "Jenkins Dashboard", "HIGH",
          "/jenkins/", status=[200],
          contains=["Jenkins", "Dashboard"],
          description="CI/CD pipeline management exposed"),

    Probe("exposed-grafana", "Grafana Login", "MEDIUM",
          "/grafana/login", status=[200],
          contains=["Grafana", "grafana"],
          description="Metrics dashboard login exposed"),

    Probe("exposed-kibana", "Kibana Dashboard", "HIGH",
          "/app/kibana", status=[200],
          contains=["Kibana", "kibana"],
          description="Elasticsearch Kibana dashboard exposed"),

    Probe("exposed-actuator", "Spring Boot Actuator", "HIGH",
          "/actuator", status=[200],
          contains=['"_links"'],
          description="Spring Boot management endpoints exposed"),

    Probe("exposed-actuator-env", "Spring Boot /actuator/env", "CRITICAL",
          "/actuator/env", status=[200],
          contains=["propertySources", "activeProfiles"],
          description="Environment variables and secrets exposed"),

    Probe("exposed-swagger", "Swagger UI Exposed", "MEDIUM",
          "/swagger-ui.html", status=[200],
          contains=["swagger-ui", "Swagger"],
          description="API documentation with endpoints exposed"),

    Probe("exposed-swagger-json", "OpenAPI Spec Exposed", "LOW",
          "/api-docs", status=[200],
          contains=['"swagger"', '"openapi"'],
          description="Machine-readable API spec exposed"),

    Probe("exposed-graphql-playground", "GraphQL Playground", "MEDIUM",
          "/graphql", status=[200],
          contains=["GraphQL", "introspection"],
          description="GraphQL endpoint may allow introspection"),

    # ── Default / error pages ──────────────────────────────────────────────
    Probe("default-laravel-debug", "Laravel Debug Mode", "HIGH",
          "/", status=[500],
          contains=["Whoops", "Laravel", "Stack trace"],
          description="Laravel debug mode leaks stack traces"),

    Probe("default-django-debug", "Django Debug Page", "HIGH",
          "/", status=[500],
          contains=["Django", "DEBUG", "Traceback"],
          description="Django DEBUG=True leaks code and settings"),

    Probe("default-rails-error", "Rails Error Page", "MEDIUM",
          "/", status=[500],
          contains=["Ruby on Rails", "Application Trace"],
          description="Rails error page leaks file paths"),

    # ── Environment / config leaks ─────────────────────────────────────────
    Probe("exposed-env-file", "Exposed .env File", "CRITICAL",
          "/.env", status=[200],
          contains=["APP_KEY", "DB_PASSWORD", "SECRET"],
          not_contains=["<html", "404"],
          description=".env file with secrets is publicly accessible"),

    Probe("exposed-git-config", "Git Config Exposed", "HIGH",
          "/.git/config", status=[200],
          contains=["[core]", "repositoryformatversion"],
          description=".git/config reveals repo structure"),

    Probe("exposed-ds-store", ".DS_Store Exposed", "LOW",
          "/.DS_Store", status=[200],
          header_key="content-type",
          description="macOS .DS_Store leaks directory structure"),

    Probe("exposed-backup", "Backup File Exposed", "HIGH",
          "/backup.zip", status=[200],
          description="Backup archive accessible"),

    Probe("exposed-backup-sql", "SQL Dump Exposed", "CRITICAL",
          "/backup.sql", status=[200],
          contains=["CREATE TABLE", "INSERT INTO"],
          description="SQL database dump accessible"),

    # ── Headers / security config ──────────────────────────────────────────
    Probe("missing-hsts", "HSTS Header Missing", "MEDIUM",
          "/", status=[200],
          not_contains=[],  # checked via header logic below
          description="Strict-Transport-Security header not set"),

    Probe("missing-csp", "CSP Header Missing", "LOW",
          "/",
          description="Content-Security-Policy header not set"),

    Probe("server-version-leak", "Server Version Disclosure", "LOW",
          "/",
          description="Server header reveals version info"),

    # ── Path traversal / SSRF quick probes ────────────────────────────────
    Probe("path-traversal-etc-passwd", "Path Traversal (LFI probe)", "CRITICAL",
          "/../../../../etc/passwd",
          contains=["root:x:", "daemon:"],
          description="Potential local file inclusion vulnerability"),

    Probe("exposed-debug-console", "Debug Console Exposed", "CRITICAL",
          "/console", status=[200],
          contains=["Python", "Werkzeug", "Interactive Console"],
          description="Werkzeug interactive Python console exposed"),

    # ── Common CVE fingerprints ────────────────────────────────────────────
    Probe("cve-2017-5638-struts", "Apache Struts RCE (CVE-2017-5638)", "CRITICAL",
          "/",
          headers={"Content-Type": "%{(#_='multipart/form-data')}"},
          contains=["ognl", "struts"],
          description="Apache Struts OGNL injection fingerprint"),

    Probe("cve-2021-41773-apache", "Apache Path Traversal (CVE-2021-41773)", "CRITICAL",
          "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
          contains=["root:x:"],
          description="Apache 2.4.49 path traversal exploit"),

    Probe("cve-2022-22965-spring4shell", "Spring4Shell (CVE-2022-22965)", "CRITICAL",
          "/",
          headers={"suffix": "%>//", "c1": "Runtime", "c2": "<%", "DNT": "1"},
          status=[200],
          description="Spring Framework RCE fingerprint probe"),
]


# ── HTTP probe executor ───────────────────────────────────────────────────────
@dataclass
class Finding:
    probe_id:    str
    name:        str
    severity:    str
    url:         str
    description: str
    evidence:    str = ""


def _run_probe(session: requests.Session, base_url: str, probe: Probe, timeout: int) -> Optional[Finding]:
    url = urljoin(base_url.rstrip("/") + "/", probe.path.lstrip("/"))
    method = probe.method.upper()
    hdrs = {**probe.headers}

    try:
        resp = session.request(
            method, url,
            data=probe.body or None,
            headers=hdrs,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
    except requests.RequestException:
        return None

    body = resp.text[:4000]

    # Status check
    if probe.status and resp.status_code not in probe.status:
        return None

    # Special header-based checks
    if probe.id == "missing-hsts":
        if "strict-transport-security" not in resp.headers:
            return Finding(probe.id, probe.name, probe.severity, url, probe.description,
                           "Header 'Strict-Transport-Security' absent")
        return None

    if probe.id == "missing-csp":
        if "content-security-policy" not in resp.headers:
            return Finding(probe.id, probe.name, probe.severity, url, probe.description,
                           "Header 'Content-Security-Policy' absent")
        return None

    if probe.id == "server-version-leak":
        server = resp.headers.get("server", "")
        if re.search(r"\d+\.\d+", server):
            return Finding(probe.id, probe.name, probe.severity, url, probe.description,
                           f"Server: {server}")
        return None

    # Body contains checks
    if probe.contains and not all(s.lower() in body.lower() for s in probe.contains):
        return None

    # Body must NOT contain
    if probe.not_contains and any(s.lower() in body.lower() for s in probe.not_contains):
        return None

    # Regex check
    if probe.regex and not re.search(probe.regex, body, re.I):
        return None

    # Extract brief evidence snippet
    evidence = ""
    if probe.contains:
        for needle in probe.contains:
            idx = body.lower().find(needle.lower())
            if idx >= 0:
                evidence = body[max(0, idx-20):idx+60].strip().replace("\n", " ")
                break

    return Finding(probe.id, probe.name, probe.severity, url, probe.description, evidence)


# ── Main module ───────────────────────────────────────────────────────────────
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "dim yellow",
    "INFO":     "dim",
}


class NucleiLite(ArgusModule):
    name = "Nuclei Lite — CVE & Misconfiguration Scanner"
    description = "HTTP-based probe scanner for common vulns (no binary required)"

    def run(self, target: str, threads: int, opts: dict) -> None:
        self.banner()
        domain   = self.clean(target)
        base_url = ensure_url_format(domain)
        timeout  = int(opts.get("timeout", 8))
        threads  = max(1, min(threads, 30))
        severity_filter = opts.get("severity", "").upper()

        console.print(f"[cyan][*] Target: [bold]{base_url}[/bold][/cyan]")
        console.print(f"[dim]    Probes: {len(PROBES)}  |  Threads: {threads}  |  Timeout: {timeout}s[/dim]\n")

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = requests.Session()
        session.headers.update(self.headers)

        findings: list[Finding] = []

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_run_probe, session, base_url, p, timeout): p for p in PROBES}
            done = 0
            for fut in as_completed(futures):
                done += 1
                result = fut.result()
                if result:
                    findings.append(result)
                    sty = SEV_STYLE.get(result.severity, "white")
                    console.print(f"  [{sty}][{result.severity}][/{sty}]  {result.name}")

        # Sort by severity
        findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 99))

        # Filter
        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]

        console.print()

        if not findings:
            console.print(Panel(
                "[green][+] No vulnerabilities or misconfigurations detected.[/green]\n"
                "[dim]This is a lightweight heuristic scan — a clean result does not guarantee security.[/dim]",
                title="Result", style="green",
            ))
            self.summary(f"Probes: {len(PROBES)}")
            return

        # Results table
        table = Table(
            title=f"Findings — {domain}  ({len(findings)} issue(s))",
            header_style="bold magenta",
            box=box.MINIMAL_HEAVY_HEAD,
        )
        table.add_column("Severity",    width=10)
        table.add_column("Name",        style="white",  overflow="fold")
        table.add_column("URL",         style="dim cyan", overflow="fold")
        table.add_column("Description", style="dim",    overflow="fold")

        for f in findings:
            sty = SEV_STYLE.get(f.severity, "white")
            table.add_row(
                f"[{sty}]{f.severity}[/{sty}]",
                f.name,
                f.url,
                f.description,
            )

        console.print(table)

        # Evidence snippets for critical/high
        critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH") and f.evidence]
        if critical_high:
            console.print("\n[bold red]Evidence snippets:[/bold red]")
            for f in critical_high[:5]:
                console.print(f"  [bold]{f.name}[/bold]")
                console.print(f"  [dim]{f.evidence[:120]}[/dim]\n")

        # Count by severity
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        summary_parts = [f"[{SEV_STYLE[s]}]{c} {s}[/{SEV_STYLE[s]}]"
                         for s, c in by_sev.items()]
        console.print("  " + "  ·  ".join(summary_parts))

        self.summary(f"Probes: {len(PROBES)}  |  Found: {len(findings)}")
        console.print("[green][*] Nuclei Lite scan complete[/green]\n")


if __name__ == "__main__":
    NucleiLite.entrypoint()
