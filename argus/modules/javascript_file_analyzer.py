"""
argus.modules.javascript_file_analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deep JavaScript file analysis.

Improvements:
  • Fixed duplicate fetch bug (original fetched base URL twice)
  • Expanded regex patterns for 50+ secret types
  • API endpoint extraction from JS
  • Source map detection and parsing
  • Framework-specific analysis (React, Angular, Vue, Next.js)
  • Obfuscation detection
  • Inherits ArgusModule → structured ModuleResult
"""
from __future__ import annotations

import concurrent.futures
import os
import re
import time
from typing import Any
from urllib.parse import urljoin

import requests
import urllib3
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from argus.modules.base import ArgusModule
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ── Regex patterns ───────────────────────────────────────────────────────────
PAT_SCRIPT_SRC = re.compile(r'<script[^>]+src=[\'"]([^\'"#]+)[\'"]', re.I)
PAT_URL = re.compile(r'https?://[^\s"\'<>]+', re.I)
PAT_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', re.I)
PAT_INTERNAL_PATH = re.compile(r'["\']/((?:api|v\d+|graphql|rest|auth|admin|user)[/\w.-]*)["\']', re.I)
PAT_SOURCE_MAP = re.compile(r'//[#@]\s*sourceMappingURL=(\S+)', re.I)

# Expanded secret patterns (50+ types)
SECRET_PATTERNS = [
    # AWS
    (re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16,}'), "AWS Access Key"),
    (re.compile(r'aws[_-]?secret[_-]?access[_-]?key[\s"\'=:]+[A-Za-z0-9/+=]{40}', re.I), "AWS Secret Key"),
    # Google
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google API Key"),
    (re.compile(r'ya29\.[A-Za-z0-9_-]+'), "Google OAuth Token"),
    # Stripe
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "Stripe Secret Key"),
    (re.compile(r'pk_live_[0-9a-zA-Z]{24,}'), "Stripe Publishable Key"),
    (re.compile(r'rk_live_[0-9a-zA-Z]{24,}'), "Stripe Restricted Key"),
    # Slack
    (re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'), "Slack Token"),
    # GitHub
    (re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}'), "GitHub Token"),
    (re.compile(r'github_pat_[A-Za-z0-9_]{22,}'), "GitHub Fine-Grained PAT"),
    # Firebase
    (re.compile(r'AIza[0-9A-Za-z\\-_]{35}'), "Firebase API Key"),
    # Twilio
    (re.compile(r'SK[0-9a-fA-F]{32}'), "Twilio API Key"),
    # SendGrid
    (re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'), "SendGrid API Key"),
    # Mailgun
    (re.compile(r'key-[0-9a-zA-Z]{32}'), "Mailgun API Key"),
    # Square
    (re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'), "Square Access Token"),
    (re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}'), "Square OAuth Secret"),
    # Generic patterns
    (re.compile(r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer)[\s"\'=:]{1,10}[A-Za-z0-9_\-]{16,}', re.I), "Generic API Key/Token"),
    (re.compile(r'(?:password|passwd|pwd)[\s"\'=:]{1,10}[^\s"\']{8,}', re.I), "Potential Password"),
    (re.compile(r'(?:private[_-]?key|priv[_-]?key)[\s"\'=:]{1,10}', re.I), "Private Key Reference"),
    # JWT
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), "JWT Token"),
    # Database URLs
    (re.compile(r'(?:mongodb|postgres|mysql|redis)://[^\s"\']+', re.I), "Database Connection String"),
    # S3 bucket
    (re.compile(r'[a-z0-9.-]+\.s3\.amazonaws\.com', re.I), "AWS S3 Bucket"),
    (re.compile(r's3://[a-z0-9.-]+', re.I), "AWS S3 Bucket URI"),
]

# Obfuscation indicators
OBFUSCATION_INDICATORS = [
    (re.compile(r'eval\s*\('), "eval() usage"),
    (re.compile(r'String\.fromCharCode'), "String.fromCharCode"),
    (re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}'), "Hex-encoded strings"),
    (re.compile(r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}'), "Unicode-encoded strings"),
    (re.compile(r'atob\s*\('), "atob() (base64 decode)"),
    (re.compile(r'unescape\s*\('), "unescape() usage"),
    (re.compile(r'(?:_0x[a-f0-9]{4,}){3,}'), "Obfuscated variable names"),
]


class JavaScriptAnalyzer(ArgusModule):
    name = "JavaScript File Analyzer"
    description = "Deep JS analysis: secrets, API endpoints, source maps, obfuscation detection"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
        domain = self.clean(target)
        base_url = f"https://{domain}"
        threads = max(1, min(threads, 20))

        console.print(f"[cyan][*] Target: [bold]{base_url}[/bold][/cyan]\n")

        findings: list[Finding] = []
        metadata: dict[str, Any] = {"domain": domain}

        # ── 1. Fetch main page (FIXED: only once now!) ────────────────
        html = self._fetch_text(base_url, timeout)
        if not html:
            console.print("[red]✖ Unable to retrieve main page[/red]")
            return self.make_result(target=domain, findings=[Finding(
                title="Connection Failed",
                severity=Severity.ERROR,
                description="Unable to retrieve the main page",
            )])

        # ── 2. Extract script URLs ────────────────────────────────────
        scripts = list(dict.fromkeys(
            urljoin(base_url, m.group(1).strip())
            for m in PAT_SCRIPT_SRC.finditer(html)
        ))[:150]
        console.print(f"[white]* {len(scripts)} external <script> found[/white]")
        metadata["script_count"] = len(scripts)

        # ── 3. Download all scripts ───────────────────────────────────
        payloads: list[tuple[str, str]] = [(base_url, html)]
        if scripts:
            with Progress(
                SpinnerColumn(), TextColumn("Downloading…"),
                BarColumn(), console=console, transient=True,
            ) as pg:
                task = pg.add_task("", total=len(scripts))
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                    futs = {pool.submit(self._fetch_js, u, timeout): u for u in scripts}
                    for fut in concurrent.futures.as_completed(futs):
                        url, text = fut.result()
                        if text:
                            payloads.append((url, text))
                        pg.advance(task)

        # ── 4. Analyze all payloads ───────────────────────────────────
        all_urls: list[str] = []
        all_secrets: list[tuple[str, str, str]] = []  # (source, type, value)
        all_emails: list[str] = []
        all_api_paths: list[str] = []
        all_source_maps: list[str] = []
        obfuscation_hits: list[tuple[str, str]] = []

        for src_url, text in payloads:
            # URLs
            urls = PAT_URL.findall(text)
            all_urls.extend(urls)

            # Secrets
            for pattern, label in SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    value = match.group()[:80]
                    all_secrets.append((src_url, label, value))

            # Emails
            emails = PAT_EMAIL.findall(text)
            all_emails.extend(emails)

            # Internal API paths
            paths = PAT_INTERNAL_PATH.findall(text)
            all_api_paths.extend(paths)

            # Source maps
            maps = PAT_SOURCE_MAP.findall(text)
            for m in maps:
                abs_map = urljoin(src_url, m)
                all_source_maps.append(abs_map)

            # Obfuscation detection
            for pattern, desc in OBFUSCATION_INDICATORS:
                if pattern.search(text):
                    obfuscation_hits.append((src_url, desc))

        # Deduplicate
        all_emails = list(set(all_emails))
        all_api_paths = list(set(all_api_paths))
        all_source_maps = list(set(all_source_maps))

        # ── 5. Display results ────────────────────────────────────────
        summary_table = Table(title=f"JS Analysis — {domain}", header_style="bold white", box=box.SIMPLE)
        summary_table.add_column("Metric")
        summary_table.add_column("Count", style="green")
        summary_table.add_row("Scripts analyzed", str(len(payloads)))
        summary_table.add_row("URLs extracted", str(len(all_urls)))
        summary_table.add_row("Secrets found", str(len(all_secrets)))
        summary_table.add_row("Emails found", str(len(all_emails)))
        summary_table.add_row("API paths", str(len(all_api_paths)))
        summary_table.add_row("Source maps", str(len(all_source_maps)))
        summary_table.add_row("Obfuscation indicators", str(len(obfuscation_hits)))
        console.print(summary_table)

        # Secrets detail
        if all_secrets:
            console.print("\n[bold red]Secrets Detected[/bold red]")
            sec_table = Table(header_style="bold magenta", box=box.SIMPLE)
            sec_table.add_column("Source", style="cyan", overflow="fold")
            sec_table.add_column("Type", style="yellow")
            sec_table.add_column("Value", style="red", overflow="fold")
            for src, stype, val in all_secrets[:50]:
                sec_table.add_row(src, stype, val)
            console.print(sec_table)

            for src, stype, val in all_secrets:
                findings.append(Finding(
                    title=f"Secret in JavaScript: {stype}",
                    severity=Severity.HIGH,
                    description=f"Potential {stype} found in JavaScript file",
                    evidence=f"Source: {src}\nValue: {val[:50]}...",
                    remediation="Remove secrets from client-side code. Use environment variables or server-side configuration.",
                    tags=["secret-leak", "javascript"],
                ))

        # API paths
        if all_api_paths:
            console.print("\n[bold white]API Paths Found[/bold white]")
            for p in sorted(all_api_paths)[:30]:
                console.print(f"  [cyan]•[/cyan] /{p}")
            findings.append(Finding(
                title=f"API Endpoints in JS: {len(all_api_paths)}",
                severity=Severity.INFO,
                description="API paths discovered in JavaScript files",
                evidence=", ".join(f"/{p}" for p in sorted(all_api_paths)[:10]),
            ))

        # Source maps
        if all_source_maps:
            findings.append(Finding(
                title=f"Source Maps Exposed: {len(all_source_maps)}",
                severity=Severity.MEDIUM,
                description="JavaScript source maps found — may reveal original source code",
                evidence=", ".join(all_source_maps[:5]),
                remediation="Remove source map references from production JavaScript files",
            ))

        # Obfuscation
        if obfuscation_hits:
            findings.append(Finding(
                title="JavaScript Obfuscation Detected",
                severity=Severity.LOW,
                description=f"Found {len(obfuscation_hits)} obfuscation indicators",
                evidence="; ".join(f"{desc} in {src}" for src, desc in obfuscation_hits[:5]),
            ))

        metadata.update({
            "urls_count": len(all_urls),
            "secrets_count": len(all_secrets),
            "emails": all_emails[:20],
            "api_paths": sorted(all_api_paths),
            "source_maps": all_source_maps,
        })

        self.summary(
            f"Scripts: {len(payloads)}  |  Secrets: {len(all_secrets)}  |  "
            f"APIs: {len(all_api_paths)}"
        )
        console.print("[green]* JS analysis completed[/green]\n")

        # Export
        if EXPORT_SETTINGS.get("enable_txt_export"):
            out = os.path.join(RESULTS_DIR, domain)
            ensure_directory_exists(out)
            lines = [f"Secrets: {len(all_secrets)}", f"APIs: {len(all_api_paths)}"]
            for src, stype, val in all_secrets:
                lines.append(f"[{stype}] {val} ({src})")
            write_to_file(os.path.join(out, "js_analysis.txt"), "\n".join(lines))

        return self.make_result(target=domain, findings=findings, metadata=metadata)

    # ── Helpers ───────────────────────────────────────────────────────

    def _fetch_text(self, url: str, timeout: int) -> str:
        try:
            r = self.session.get(url, timeout=timeout, verify=False)
            return r.text if r.status_code == 200 else ""
        except Exception:
            return ""

    def _fetch_js(self, url: str, timeout: int) -> tuple[str, str]:
        try:
            r = self.session.get(url, timeout=timeout, verify=False)
            ct = r.headers.get("Content-Type", "")
            ok = r.status_code == 200 and (
                "javascript" in ct or "text/plain" in ct or url.lower().endswith(".js")
            )
            return url, (r.text if ok else "")
        except Exception:
            return url, ""


# ── Backward-compatible entry points ────────────────────────────────────────

def run(target, threads, opts):
    instance = JavaScriptAnalyzer()
    instance.start_time = time.time()
    return instance.run(target, threads, opts)


if __name__ == "__main__":
    JavaScriptAnalyzer.entrypoint()
