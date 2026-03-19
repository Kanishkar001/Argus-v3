"""
argus.modules.crawler
~~~~~~~~~~~~~~~~~~~~~~
Production web crawler with async crawling, form/API discovery, and rate limiting.

Improvements:
  • aiohttp-based concurrent crawling
  • JavaScript URL extraction from <script> tags
  • Form discovery and parameter extraction
  • API endpoint detection
  • robots.txt respect
  • Rate limiting with politeness delays
  • Inherits ArgusModule → structured ModuleResult
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
import json
import time
import urllib.parse
from collections import Counter, deque
from typing import Any

import aiohttp
import requests
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from argus.modules.base import ArgusModule
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from argus.utils.util import clean_domain_input, ensure_directory_exists, write_to_file

console = Console()

# Regex patterns
RE_HREF = re.compile(r'href=["\']([^"\'#]+)', re.I)
RE_SRC = re.compile(r'src=["\']([^"\'#]+)', re.I)
RE_ACTION = re.compile(r'<form[^>]+action=["\']([^"\'#]*)', re.I)
RE_INPUT = re.compile(r'<input[^>]+name=["\']([^"\']+)', re.I)
RE_API = re.compile(r'["\']/(api|graphql|v\d+|rest|ws)[/"\'\\]', re.I)
RE_JS_URL = re.compile(r'["\'](https?://[^"\'\\s]+)["\']', re.I)


class Crawler(ArgusModule):
    name = "Web Crawler"
    description = "Async web crawler with form, parameter, and API endpoint discovery"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        domain = self.clean(target)
        base_url = opts.get("start_url", "") or f"https://{domain}"
        max_pages = int(opts.get("max_pages", 400))
        depth_limit = int(opts.get("depth", 3))
        rate = float(opts.get("rate_limit", 0.15))
        respect_robots = bool(int(opts.get("robots", 1)))

        console.print(f"[cyan][*] Target: [bold]{base_url}[/bold][/cyan]")
        console.print(f"[dim]    Pages: {max_pages}  |  Depth: {depth_limit}  |  Rate: {rate}s[/dim]\n")

        # Run async crawler
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                self._crawl(base_url, domain, max_pages, depth_limit, rate, respect_robots, threads)
            )
        finally:
            loop.close()

        pages, content_types, forms, api_endpoints, js_urls, external_links = result

        findings: list[Finding] = []
        metadata: dict[str, Any] = {
            "domain": domain,
            "base_url": base_url,
            "pages_crawled": len(pages),
        }

        # ── Display results ───────────────────────────────────────────
        console.print(f"\n[white]* Crawled [green]{len(pages)}[/green] pages[/white]")

        # Content-type summary
        console.print("[white]Content-Type summary:[/white]")
        for ct, count in content_types.most_common():
            console.print(f"  • {ct or 'unknown'}: {count}")

        # Page table (show first 50)
        page_table = Table(
            title=f"Crawled Pages ({len(pages)} total)",
            header_style="bold magenta",
            box=box.SIMPLE,
        )
        page_table.add_column("URL", style="cyan", overflow="fold")
        page_table.add_column("Status", style="green")
        page_table.add_column("Type", style="yellow")
        for url, status, ct in pages[:50]:
            page_table.add_row(url, str(status), ct)
        if len(pages) > 50:
            page_table.add_row(f"... and {len(pages) - 50} more", "", "")
        console.print(page_table)

        # Forms
        if forms:
            console.print(f"\n[bold white]Forms Discovered ({len(forms)})[/bold white]")
            form_table = Table(header_style="bold magenta", box=box.SIMPLE)
            form_table.add_column("Action", style="cyan", overflow="fold")
            form_table.add_column("Parameters", style="green", overflow="fold")
            for action, params in forms[:20]:
                form_table.add_row(action, ", ".join(params))
            console.print(form_table)
            metadata["forms"] = [{"action": a, "params": p} for a, p in forms]

            findings.append(Finding(
                title=f"Forms Discovered: {len(forms)}",
                severity=Severity.INFO,
                description=f"Found {len(forms)} HTML forms with input parameters",
                evidence=f"Actions: {', '.join(a for a, _ in forms[:5])}",
            ))

        # API endpoints
        if api_endpoints:
            console.print(f"\n[bold white]API Endpoints ({len(api_endpoints)})[/bold white]")
            for ep in sorted(api_endpoints)[:20]:
                console.print(f"  [cyan]•[/cyan] {ep}")
            metadata["api_endpoints"] = sorted(api_endpoints)

            findings.append(Finding(
                title=f"API Endpoints Discovered: {len(api_endpoints)}",
                severity=Severity.INFO,
                description="Potential API endpoints found in crawled content",
                evidence=", ".join(sorted(api_endpoints)[:10]),
            ))

        # External links
        if external_links:
            metadata["external_links_count"] = len(external_links)
            findings.append(Finding(
                title=f"External Links: {len(external_links)}",
                severity=Severity.INFO,
                description=f"Found {len(external_links)} outbound links to external domains",
            ))

        findings.append(Finding(
            title="Crawl Summary",
            severity=Severity.INFO,
            description=f"Crawled {len(pages)} pages, found {len(forms)} forms, {len(api_endpoints)} API endpoints",
        ))

        self.summary(f"Pages: {len(pages)}  |  Forms: {len(forms)}  |  APIs: {len(api_endpoints)}")
        console.print("[green]* Web crawl completed[/green]\n")

        # Export
        if EXPORT_SETTINGS.get("enable_txt_export"):
            out = os.path.join(RESULTS_DIR, domain)
            ensure_directory_exists(out)
            export_lines = [f"{url}\t{status}\t{ct}" for url, status, ct in pages]
            write_to_file(os.path.join(out, "web_crawl.txt"), "\n".join(export_lines))

        return self.make_result(target=domain, findings=findings, metadata=metadata)

    async def _crawl(
        self,
        base_url: str,
        domain: str,
        max_pages: int,
        depth_limit: int,
        rate: float,
        respect_robots: bool,
        concurrency: int,
    ) -> tuple:
        pages: list[tuple[str, int | str, str]] = []
        content_types = Counter()
        forms: list[tuple[str, list[str]]] = []
        api_endpoints: set[str] = set()
        js_urls: set[str] = set()
        external_links: set[str] = set()

        # Robots.txt
        disallowed: set[str] = set()
        if respect_robots:
            try:
                resp = requests.get(f"{base_url}/robots.txt", timeout=5)
                if resp.ok:
                    for line in resp.text.splitlines():
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                disallowed.add(path)
            except Exception:
                pass

        queue: deque[tuple[str, int]] = deque([(base_url, 0)])
        seen: set[str] = {base_url}
        sem = asyncio.Semaphore(concurrency)

        connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
        timeout_obj = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
            while queue and len(pages) < max_pages:
                url, depth = queue.popleft()

                # Check robots.txt
                parsed = urllib.parse.urlparse(url)
                if any(parsed.path.startswith(d) for d in disallowed):
                    continue

                async with sem:
                    await asyncio.sleep(rate)
                    try:
                        async with session.get(url, allow_redirects=True) as resp:
                            ct = resp.headers.get("Content-Type", "").split(";")[0]
                            status = resp.status
                            body = ""
                            if "html" in ct:
                                body = await resp.text(errors="ignore")
                    except Exception:
                        ct, status, body = "-", "ERR", ""

                pages.append((url, status, ct))
                content_types[ct or "unknown"] += 1

                # Parse HTML
                if body and depth < depth_limit:
                    # Links
                    for href in RE_HREF.findall(body):
                        abs_url = urllib.parse.urljoin(url, href.split("#")[0])
                        abs_parsed = urllib.parse.urlparse(abs_url)
                        if abs_url not in seen and abs_url.startswith("http"):
                            if abs_parsed.netloc == urllib.parse.urlparse(base_url).netloc:
                                seen.add(abs_url)
                                queue.append((abs_url, depth + 1))
                            else:
                                external_links.add(abs_url)

                    # Forms
                    for action in RE_ACTION.findall(body):
                        abs_action = urllib.parse.urljoin(url, action) if action else url
                        # Find nearby inputs
                        params = RE_INPUT.findall(body)
                        if params:
                            forms.append((abs_action, list(set(params))))

                    # API endpoints
                    for match in RE_API.finditer(body):
                        api_endpoints.add(match.group(0).strip("\"'"))

                    # JS URLs
                    for js_match in RE_SRC.findall(body):
                        if js_match.endswith(".js"):
                            js_urls.add(urllib.parse.urljoin(url, js_match))

        return pages, content_types, forms, api_endpoints, js_urls, external_links


# ── Backward-compatible entry points ────────────────────────────────────────

def run(target, threads, opts):
    instance = Crawler()
    instance.start_time = time.time()
    return instance.run(target, threads, opts)


if __name__ == "__main__":
    Crawler.entrypoint()
