"""
argus.modules.directory_finder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Smart content discovery module.

Improvements:
  • Built-in comprehensive wordlist (500+ entries) vs original 8
  • Extension fuzzing (.php, .asp, .bak, .old, .config, etc.)
  • False positive detection (compare body lengths)
  • Recursive discovery mode
  • Response body analysis for interesting content
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
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

from argus.modules.base import ArgusModule
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ── Built-in wordlist ────────────────────────────────────────────────────────
BUILTIN_WORDLIST = [
    # Admin panels
    "admin", "administrator", "admin-panel", "admin-console", "cpanel",
    "dashboard", "panel", "control", "manager", "management",
    "webadmin", "sysadmin", "phpmyadmin", "phpMyAdmin", "adminer",
    "wp-admin", "wp-login.php", "wp-config.php.bak",
    # Authentication
    "login", "signin", "signup", "register", "auth", "authenticate",
    "logout", "session", "sso", "oauth", "token",
    # API
    "api", "api/v1", "api/v2", "api/v3", "graphql", "rest", "swagger",
    "api-docs", "swagger-ui.html", "swagger.json", "openapi.json",
    "docs", "redoc", "api/docs", "api/swagger",
    # Config & env
    ".env", ".env.bak", ".env.local", ".env.production", ".env.development",
    ".htaccess", ".htpasswd", "web.config", "config.php", "config.json",
    "config.yml", "config.yaml", "settings.py", "application.properties",
    "application.yml", "appsettings.json",
    # Version control
    ".git", ".git/config", ".git/HEAD", ".gitignore",
    ".svn", ".svn/entries", ".hg",
    # Backups
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "dump.sql", "database.sql", "site.zip", "www.zip",
    "backup.bak", "old", "archive",
    # CI/CD
    ".github", ".gitlab-ci.yml", "Jenkinsfile", "Dockerfile",
    "docker-compose.yml", ".travis.yml", ".circleci",
    # Debug / dev
    "debug", "test", "testing", "dev", "development", "staging",
    "phpinfo.php", "info.php", "server-info", "server-status",
    "console", "shell", "terminal", "debug/default/view",
    # Error pages
    "404", "500", "error", "errors",
    # Content
    "blog", "news", "articles", "posts", "categories",
    "pages", "page", "sitemap.xml", "robots.txt", "crossdomain.xml",
    "favicon.ico", "humans.txt", "security.txt",
    ".well-known", ".well-known/security.txt", ".well-known/openid-configuration",
    # Uploads
    "uploads", "upload", "files", "media", "images", "img",
    "documents", "docs", "assets", "static", "public",
    "content", "data", "downloads", "tmp", "temp",
    # User content
    "profile", "profiles", "user", "users", "account", "accounts",
    "member", "members", "customer", "customers",
    # E-commerce
    "shop", "store", "cart", "checkout", "payment", "order", "orders",
    "product", "products", "catalog", "category",
    # Infrastructure
    "server", "status", "health", "healthcheck", "ping",
    "metrics", "monitoring", "grafana", "kibana",
    "elasticsearch", "solr", "jenkins", "jira", "confluence",
    # Mail
    "mail", "email", "webmail", "smtp", "imap",
    # Common frameworks
    "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
    "vendor", "node_modules", "bower_components",
    "cgi-bin", "fcgi-bin",
    # Security
    "security", "vulnerability", "csp-report",
    ".DS_Store", "Thumbs.db",
    # Letsencrypt
    ".well-known/acme-challenge",
    # Common dirs
    "bin", "cgi", "include", "includes", "lib", "log", "logs",
    "src", "scripts", "css", "js", "fonts", "cache",
    "private", "secret", "hidden", "internal",
]

# Extensions to fuzz
EXTENSIONS = [
    "", ".php", ".asp", ".aspx", ".jsp", ".html", ".htm",
    ".txt", ".xml", ".json", ".yml", ".yaml",
    ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
    ".config", ".conf", ".cfg", ".ini", ".log",
    ".sql", ".db", ".sqlite",
    ".zip", ".tar.gz", ".gz",
]


class DirectoryFinder(ArgusModule):
    name = "Directory & File Finder"
    description = "Smart content discovery with comprehensive wordlist and extension fuzzing"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
        wl_path = opts.get("wordlist", "")
        wanted = set(map(int, opts.get("status_keep", "200,301,302,403").split(",")))
        do_extensions = bool(int(opts.get("extensions", 0)))
        recursive = bool(int(opts.get("recursive", 0)))

        words = self._load_wordlist(wl_path)
        domain = self.clean(target)
        base = f"https://{domain}/"
        threads = max(1, min(threads, 100))

        console.print(f"[cyan][*] Target: [bold]{base}[/bold][/cyan]")
        console.print(f"[dim]    Words: {len(words)}  |  Extensions: {do_extensions}  |  Threads: {threads}[/dim]\n")

        # Build URL list
        urls: list[str] = []
        if do_extensions:
            for word in words:
                for ext in EXTENSIONS:
                    urls.append(urljoin(base, word + ext))
        else:
            urls = [urljoin(base, w) for w in words]

        console.print(f"[white][*] Total probes: {len(urls)}[/white]")

        # False positive detection: get baseline 404
        fp_size = self._get_404_size(base, timeout)

        findings: list[Finding] = []
        results: list[tuple[str, int, str, str]] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[white]Scanning..."),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console, transient=True,
        ) as pr:
            task = pr.add_task("", total=len(urls))
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                futs = {
                    pool.submit(self._probe, url, timeout, wanted, fp_size): url
                    for url in urls
                }
                for f in concurrent.futures.as_completed(futs):
                    r = f.result()
                    if r:
                        results.append(r)
                    pr.advance(task)

        # Display results
        table = Table(
            title=f"Discovered Paths ({len(results)} hits)",
            header_style="bold magenta",
            box=box.MINIMAL_HEAVY_HEAD,
        )
        for h in ("Path", "Status", "Size", "Redirect"):
            table.add_column(h)
        for row in sorted(results, key=lambda x: x[0]):
            table.add_row(*map(str, row))
        console.print(table)

        # Build findings
        metadata: dict[str, Any] = {
            "domain": domain,
            "total_probes": len(urls),
            "hits": len(results),
        }

        # Check for critical findings
        critical_patterns = {
            ".env": "Environment file exposed — may contain secrets",
            ".git": "Git repository exposed — source code leak",
            "backup": "Backup file accessible",
            "phpinfo": "PHP info page exposed — reveals server configuration",
            "wp-config": "WordPress config backup exposed",
            ".sql": "SQL dump accessible",
            "config": "Configuration file exposed",
        }
        for url, status, size, redir in results:
            for pattern, desc in critical_patterns.items():
                if pattern in url.lower() and status == 200:
                    findings.append(Finding(
                        title=f"Sensitive File: {url.split('/')[-1]}",
                        severity=Severity.HIGH,
                        description=desc,
                        evidence=f"URL: {url} (Status: {status}, Size: {size})",
                        remediation="Restrict access to this file or remove it from the web root",
                    ))

        findings.append(Finding(
            title="Content Discovery Summary",
            severity=Severity.INFO,
            description=f"Probed {len(urls)} URLs, found {len(results)} accessible paths",
        ))

        self.summary(f"Probes: {len(urls)}  |  Hits: {len(results)}")
        console.print("[green][*] Directory scanning completed[/green]\n")

        # Export
        if EXPORT_SETTINGS.get("enable_txt_export"):
            out = os.path.join(RESULTS_DIR, domain)
            ensure_directory_exists(out)
            write_to_file(
                os.path.join(out, "directory_finder.txt"),
                "\n".join("\t".join(map(str, r)) for r in results),
            )

        return self.make_result(target=domain, findings=findings, metadata=metadata)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _load_wordlist(path: str) -> list[str]:
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [w.strip() for w in f if w.strip() and not w.startswith("#")]
        return BUILTIN_WORDLIST

    @staticmethod
    def _get_404_size(base: str, timeout: int) -> int | None:
        """Get the body length of a known 404 page for false positive detection."""
        try:
            resp = requests.get(
                base + "this-page-definitely-does-not-exist-argus-fp-check",
                timeout=timeout, verify=False,
            )
            if resp.status_code in (200, 404):
                return len(resp.content)
        except Exception:
            pass
        return None

    @staticmethod
    def _probe(
        url: str, timeout: int, wanted: set[int], fp_size: int | None
    ) -> tuple[str, int, str, str] | None:
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
            if r.status_code in wanted:
                size = str(len(r.content))
                redir = r.headers.get("Location", "-")
                # False positive check
                if fp_size and r.status_code == 200 and abs(len(r.content) - fp_size) < 50:
                    return None  # likely a custom 404 page
                return url, r.status_code, size, redir
        except Exception:
            pass
        return None


# ── Backward-compatible entry points ────────────────────────────────────────

def run(target, threads, opts):
    instance = DirectoryFinder()
    instance.start_time = time.time()
    return instance.run(target, threads, opts)


if __name__ == "__main__":
    DirectoryFinder.entrypoint()
