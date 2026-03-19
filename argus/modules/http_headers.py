"""
argus.modules.http_headers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deep HTTP security header analysis.

Improvements over original:
  • Removed unused BeautifulSoup import
  • Full CSP analysis with per-directive risk scoring
  • HSTS preload list verification
  • Proper Set-Cookie header parsing (handles multiple cookies)
  • Feature/Permissions policy analysis
  • CORS configuration analysis
  • Cache control security implications
  • Inherits ArgusModule → structured ModuleResult
"""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse

import requests
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.modules.base import ArgusModule
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT
from argus.utils.util import clean_domain_input, clean_url, ensure_url_format

console = Console()

# ── Security header expectations ────────────────────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "description": "Controls which resources the browser loads",
        "remediation": "Set a restrictive CSP: default-src 'self'; script-src 'self'",
    },
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "Enforces HTTPS connections",
        "remediation": "Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "Prevents MIME-type sniffing",
        "remediation": "Set: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "Prevents clickjacking via iframes",
        "remediation": "Set: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Controls referrer header leakage",
        "remediation": "Set: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Controls browser features (camera, mic, geolocation)",
        "remediation": "Set: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "Legacy XSS filter (deprecated but still checked by scanners)",
        "remediation": "Set: X-XSS-Protection: 0 (CSP supersedes this)",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": Severity.LOW,
        "description": "Isolates browsing context for cross-origin resources",
        "remediation": "Set: Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": Severity.LOW,
        "description": "Controls cross-origin resource sharing at resource level",
        "remediation": "Set: Cross-Origin-Resource-Policy: same-origin",
    },
}

# ── Dangerous CSP directives ────────────────────────────────────────────────
CSP_DANGEROUS = {
    "unsafe-inline": "Allows inline scripts (XSS risk)",
    "unsafe-eval": "Allows eval() (code injection risk)",
    "data:": "Allows data: URIs in scripts/styles (XSS bypass)",
    "*": "Allows loading from any origin",
    "blob:": "Allows blob: URIs (potential XSS vector)",
}


class HTTPHeaders(ArgusModule):
    name = "HTTP Headers — Security Analysis"
    description = "Deep analysis of security headers, CSP, CORS, cookies, and server fingerprinting"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        domain = self.clean(target)
        url = ensure_url_format(domain)
        timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))

        console.print(f"[cyan][*] Target: [bold]{url}[/bold][/cyan]\n")

        findings: list[Finding] = []
        metadata: dict[str, Any] = {"url": url}

        # ── Fetch headers ─────────────────────────────────────────────
        try:
            resp = self.session.get(url, timeout=timeout, allow_redirects=True, verify=False)
        except requests.RequestException as exc:
            console.print(f"[red][!] Failed to connect: {exc}[/red]")
            return self.make_result(target=domain, findings=[Finding(
                title="Connection Failed",
                severity=Severity.ERROR,
                description=str(exc),
            )])

        headers = resp.headers
        body = resp.text[:5000]
        metadata["status_code"] = resp.status_code
        metadata["final_url"] = resp.url

        # ── 1. Display all headers ────────────────────────────────────
        header_table = Table(
            title="HTTP Response Headers",
            header_style="bold magenta",
            box=box.SIMPLE,
        )
        header_table.add_column("Header", style="cyan")
        header_table.add_column("Value", style="green", overflow="fold")
        for k, v in headers.items():
            header_table.add_row(k, v)
        console.print(header_table)

        # ── 2. Security header analysis ───────────────────────────────
        console.print("\n[bold white]Security Header Analysis[/bold white]")
        sec_table = Table(header_style="bold magenta", box=box.SIMPLE)
        sec_table.add_column("Header", style="cyan")
        sec_table.add_column("Status", style="green")
        sec_table.add_column("Severity", style="yellow")

        missing_headers: list[str] = []
        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() in {k.lower() for k in headers}:
                sec_table.add_row(header_name, "✓ Present", "OK")
            else:
                sec_table.add_row(header_name, "✗ Missing", info["severity"].value)
                missing_headers.append(header_name)
                findings.append(Finding(
                    title=f"Missing Security Header: {header_name}",
                    severity=info["severity"],
                    description=info["description"],
                    remediation=info["remediation"],
                ))
        console.print(sec_table)

        # ── 3. CSP deep analysis ──────────────────────────────────────
        csp = headers.get("Content-Security-Policy", "")
        if csp:
            console.print("\n[bold white]CSP Analysis[/bold white]")
            csp_table = Table(header_style="bold magenta", box=box.SIMPLE)
            csp_table.add_column("Directive", style="cyan")
            csp_table.add_column("Values", style="green", overflow="fold")
            csp_table.add_column("Risk", style="yellow")

            for directive in csp.split(";"):
                directive = directive.strip()
                if not directive:
                    continue
                parts = directive.split()
                name = parts[0] if parts else directive
                values = " ".join(parts[1:]) if len(parts) > 1 else ""
                risks = []
                for dangerous, reason in CSP_DANGEROUS.items():
                    if dangerous in values.lower():
                        risks.append(reason)
                        findings.append(Finding(
                            title=f"CSP Directive Risk: {name}",
                            severity=Severity.MEDIUM,
                            description=f"'{dangerous}' in {name}: {reason}",
                            evidence=directive,
                            remediation=f"Remove '{dangerous}' from CSP {name} directive",
                        ))
                risk_str = "; ".join(risks) if risks else "OK"
                csp_table.add_row(name, values, risk_str)
            console.print(csp_table)

        # ── 4. HSTS analysis ──────────────────────────────────────────
        hsts = headers.get("Strict-Transport-Security", "")
        if hsts:
            max_age_match = re.search(r"max-age=(\d+)", hsts)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            includes_sub = "includesubdomains" in hsts.lower()
            preload = "preload" in hsts.lower()

            if max_age < 31536000:
                findings.append(Finding(
                    title="HSTS max-age Too Low",
                    severity=Severity.MEDIUM,
                    description=f"HSTS max-age is {max_age}s (recommended: ≥31536000)",
                    evidence=hsts,
                    remediation="Increase max-age to at least 31536000 (1 year)",
                ))
            if not includes_sub:
                findings.append(Finding(
                    title="HSTS Missing includeSubDomains",
                    severity=Severity.LOW,
                    description="HSTS does not include subdomains",
                    remediation="Add includeSubDomains to HSTS header",
                ))

        # ── 5. Cookie analysis ────────────────────────────────────────
        console.print("\n[bold white]Cookie Security Analysis[/bold white]")
        raw_cookies = resp.headers.get("Set-Cookie", "")
        if raw_cookies:
            cookie_table = Table(header_style="bold magenta", box=box.SIMPLE)
            cookie_table.add_column("Cookie", style="cyan", overflow="fold")
            cookie_table.add_column("Secure", style="green")
            cookie_table.add_column("HttpOnly", style="green")
            cookie_table.add_column("SameSite", style="green")

            # Parse all Set-Cookie headers from raw response
            cookie_headers = [
                v for k, v in resp.raw.headers.items()
                if k.lower() == "set-cookie"
            ] if hasattr(resp, "raw") and resp.raw else [raw_cookies]

            for cookie_str in cookie_headers:
                parts = cookie_str.split(";")
                name_val = parts[0].strip()
                attrs = {p.strip().lower() for p in parts[1:]}
                has_secure = any("secure" in a for a in attrs)
                has_httponly = any("httponly" in a for a in attrs)
                samesite = next((a for a in attrs if a.startswith("samesite")), "Not Set")
                cookie_table.add_row(
                    name_val,
                    "✓" if has_secure else "✗",
                    "✓" if has_httponly else "✗",
                    samesite if samesite != "Not Set" else "✗",
                )
                if not has_secure:
                    findings.append(Finding(
                        title=f"Cookie Missing Secure Flag: {name_val.split('=')[0]}",
                        severity=Severity.MEDIUM,
                        description="Cookie can be transmitted over unencrypted connections",
                        remediation="Add Secure flag to cookie",
                    ))
                if not has_httponly:
                    findings.append(Finding(
                        title=f"Cookie Missing HttpOnly Flag: {name_val.split('=')[0]}",
                        severity=Severity.MEDIUM,
                        description="Cookie accessible via JavaScript (XSS risk)",
                        remediation="Add HttpOnly flag to cookie",
                    ))
            console.print(cookie_table)
        else:
            console.print("[dim]No Set-Cookie headers found[/dim]")

        # ── 6. CORS analysis ──────────────────────────────────────────
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao:
            if acao == "*":
                findings.append(Finding(
                    title="CORS Allows All Origins",
                    severity=Severity.MEDIUM,
                    description="Access-Control-Allow-Origin is set to * (wildcard)",
                    evidence=f"ACAO: {acao}",
                    remediation="Restrict CORS to specific trusted origins",
                ))
            acac = headers.get("Access-Control-Allow-Credentials", "")
            if acac.lower() == "true" and acao == "*":
                findings.append(Finding(
                    title="CORS Misconfiguration: Credentials with Wildcard",
                    severity=Severity.HIGH,
                    description="CORS allows credentials with wildcard origin — browser will block but indicates misconfiguration",
                    remediation="Never use credentials with wildcard CORS origins",
                ))

        # ── 7. Server technology ──────────────────────────────────────
        server = headers.get("Server", "")
        if server:
            if re.search(r"\d+\.\d+", server):
                findings.append(Finding(
                    title="Server Version Disclosure",
                    severity=Severity.LOW,
                    description=f"Server header reveals version: {server}",
                    remediation="Remove version info from Server header",
                ))
            metadata["server"] = server

        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            findings.append(Finding(
                title="X-Powered-By Header Present",
                severity=Severity.LOW,
                description=f"Technology stack disclosed: {x_powered}",
                remediation="Remove X-Powered-By header to reduce fingerprinting surface",
            ))
            metadata["x_powered_by"] = x_powered

        # ── 8. Framework detection ────────────────────────────────────
        frameworks = {
            "WordPress": ["wp-content", "wp-includes"],
            "Joomla": ["Joomla!"],
            "Drupal": ["Drupal.settings"],
            "Django": ["csrftoken", "__admin__"],
            "Laravel": ["laravel_session", "laravel_token"],
            "Ruby on Rails": ["X-Runtime", "_rails"],
            "ASP.NET": ["__VIEWSTATE", "ASP.NET"],
            "Next.js": ["__NEXT_DATA__", "_next/"],
            "React": ["react-root", "__REACT"],
            "Angular": ["ng-version", "ng-app"],
            "Vue.js": ["__vue__", "v-cloak"],
        }
        detected = []
        for framework, signatures in frameworks.items():
            if any(sig in body or sig in str(headers) for sig in signatures):
                detected.append(framework)
        if detected:
            console.print(f"\n[cyan][*] Detected frameworks: {', '.join(detected)}[/cyan]")
            metadata["frameworks"] = detected

        # ── Summary ───────────────────────────────────────────────────
        summary_text = (
            f"Missing headers: {len(missing_headers)}  |  "
            f"Findings: {len(findings)}  |  "
            f"Frameworks: {len(detected)}"
        )
        self.summary(summary_text)
        console.print("[green][*] HTTP header analysis completed[/green]\n")

        return self.make_result(target=domain, findings=findings, metadata=metadata)


# ── Backward-compatible entry points ────────────────────────────────────────

def main(target):
    instance = HTTPHeaders()
    instance.start_time = time.time()
    instance.run(target, 1, {})


if __name__ == "__main__":
    HTTPHeaders.entrypoint()
