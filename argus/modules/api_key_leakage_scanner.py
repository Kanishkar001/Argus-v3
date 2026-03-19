"""
argus.modules.api_key_leakage_scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Scans a target's HTML, JS, and inline scripts for exposed API keys,
secrets, tokens, and other credentials using pattern matching.
"""
from __future__ import annotations

import re
import sys
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.modules.base import ArgusModule
from argus.utils.util import clean_domain_input, ensure_url_format

console = Console()

# ── Credential patterns ───────────────────────────────────────────────────────
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key",      re.compile(r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})")),
    ("Google API Key",      re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Google OAuth",        re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")),
    ("GitHub Token",        re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("Slack Token",         re.compile(r"xox[baprs]-[0-9A-Za-z\-]+")),
    ("Stripe Secret Key",   re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("Stripe Publishable",  re.compile(r"pk_live_[0-9a-zA-Z]{24}")),
    ("Twilio Account SID",  re.compile(r"AC[a-zA-Z0-9]{32}")),
    ("Twilio Auth Token",   re.compile(r"(?i)twilio.*['\"]([a-f0-9]{32})['\"]")),
    ("SendGrid API Key",    re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}")),
    ("Mailchimp API Key",   re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}")),
    ("Firebase URL",        re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("Heroku API Key",      re.compile(r"(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")),
    ("Generic Bearer",      re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}")),
    ("Generic API Key",     re.compile(r"(?i)api[_\-]?key\s*[=:]\s*['\"]?([a-zA-Z0-9\-_]{16,})['\"]?")),
    ("Generic Secret",      re.compile(r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]")),
    ("Private Key Header",  re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----")),
    ("JWT Token",           re.compile(r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}")),
]

# Strings to skip (common false positives)
FALSE_POSITIVE_HINTS = {
    "example", "placeholder", "your_key", "YOUR_KEY", "xxxx", "1234",
    "test", "demo", "sample", "replace", "insert",
}


def is_false_positive(match: str) -> bool:
    m = match.lower()
    return any(hint in m for hint in FALSE_POSITIVE_HINTS)


def fetch_js_urls(base_url: str, html: str, timeout: int) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        full = urljoin(base_url, src)
        if urlparse(full).netloc == urlparse(base_url).netloc:
            urls.append(full)
    return urls[:20]  # cap at 20 JS files


def scan_text(text: str, source: str) -> list[dict]:
    findings = []
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            val = match.group(0)
            if not is_false_positive(val):
                findings.append({
                    "type":   label,
                    "value":  val[:80] + ("…" if len(val) > 80 else ""),
                    "source": source,
                })
    return findings


class ApiKeyLeakageScanner(ArgusModule):
    name = "API Key Leakage Scanner"
    description = "Detect exposed API keys, tokens, and secrets in HTML/JS"

    def run(self, target: str, threads: int, opts: dict) -> None:
        self.banner()
        domain = self.clean(target)
        base_url = ensure_url_format(domain)
        timeout = int(opts.get("timeout", self.timeout))
        depth = int(opts.get("depth", 1))

        console.print(f"[cyan][*] Scanning: [bold]{base_url}[/bold][/cyan]")
        console.print(f"[dim]    JS depth: {depth}[/dim]\n")

        all_findings: list[dict] = []
        session = requests.Session()
        session.headers.update(self.headers)

        try:
            resp = session.get(base_url, timeout=timeout, allow_redirects=True)
            html = resp.text

            # Scan main HTML
            all_findings += scan_text(html, "HTML page")

            # Scan linked JS files
            if depth >= 1:
                js_urls = fetch_js_urls(base_url, html, timeout)
                console.print(f"[dim]    Found {len(js_urls)} JS files to scan…[/dim]")
                for js_url in js_urls:
                    try:
                        jr = session.get(js_url, timeout=timeout)
                        all_findings += scan_text(jr.text, js_url.split("/")[-1][:40])
                    except Exception:
                        pass

        except requests.RequestException as e:
            console.print(f"[bold red][!] Request failed: {e}[/bold red]")
            return

        # ── Display results ────────────────────────────────────────────────
        if not all_findings:
            console.print(Panel(
                "[green][+] No exposed API keys or secrets detected.[/green]",
                title="Result", style="green"
            ))
        else:
            # Deduplicate
            seen: set[str] = set()
            unique = []
            for f in all_findings:
                key = f"{f['type']}:{f['value']}"
                if key not in seen:
                    seen.add(key)
                    unique.append(f)

            table = Table(
                title=f"Potential Credential Leaks — {domain}",
                header_style="bold red",
                box=box.MINIMAL_HEAVY_HEAD,
            )
            table.add_column("Type",   style="bold yellow", no_wrap=True)
            table.add_column("Value",  style="red",         overflow="fold")
            table.add_column("Source", style="dim cyan")

            for f in unique:
                table.add_row(f["type"], f["value"], f["source"])

            console.print(table)
            console.print(f"\n[bold red][!] {len(unique)} potential leak(s) found. Verify before reporting.[/bold red]")

        self.summary(f"Patterns: {len(PATTERNS)}")
        console.print("[green][*] API key leakage scan complete[/green]\n")


if __name__ == "__main__":
    ApiKeyLeakageScanner.entrypoint()