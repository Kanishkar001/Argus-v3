"""
argus.modules.content_discovery
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Async content discovery with crawling, sitemap, and robots.txt analysis.

Improvements:
  • FIXED: module-level sys.argv parsing (crashed on import)
  • FIXED: removed sync requests calls inside async context
  • Added depth-limited recursive crawling
  • Parameter discovery
  • Technology fingerprinting from discovered content
  • Inherits ArgusModule → structured ModuleResult
"""
from __future__ import annotations

import asyncio
import collections
import os
import re
import time
import urllib.parse
from typing import Any

import aiohttp
import bs4
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.modules.base import ArgusModule
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT
from argus.utils.util import ensure_url_format, clean_domain_input

console = Console()


class ContentDiscovery(ArgusModule):
    name = "Content Discovery"
    description = "Async content discovery: crawling, sitemap/robots analysis, tech fingerprinting"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        domain = self.clean(target)
        base = ensure_url_format(domain)
        page_limit = int(opts.get("max_pages", 100))
        include_subs = bool(int(opts.get("include_subdomains", 0)))
        depth_limit = int(opts.get("depth", 3))

        console.print(f"[cyan][*] Target: [bold]{base}[/bold][/cyan]")
        console.print(f"[dim]    Pages: {page_limit}  |  Depth: {depth_limit}[/dim]\n")

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                self._discover(base, domain, page_limit, include_subs, depth_limit)
            )
        finally:
            loop.close()

        (internal, external, css, js_files, robots_text, sitemaps,
         forms, technologies, parameters) = result

        findings: list[Finding] = []
        metadata: dict[str, Any] = {"domain": domain, "base_url": base}

        # ── Display ───────────────────────────────────────────────────
        summary_table = Table(
            title=f"Content Discovery — {base}",
            header_style="bold magenta",
            box=box.SIMPLE,
        )
        summary_table.add_column("Category", style="cyan")
        summary_table.add_column("Count", style="green")
        summary_table.add_row("robots.txt", "Yes" if robots_text else "No")
        summary_table.add_row("Sitemap Links", str(len(sitemaps)))
        summary_table.add_row("Internal Links", str(len(internal)))
        summary_table.add_row("External Links", str(len(external)))
        summary_table.add_row("CSS Files", str(len(css)))
        summary_table.add_row("JS Files", str(len(js_files)))
        summary_table.add_row("Forms Found", str(len(forms)))
        summary_table.add_row("Parameters", str(len(parameters)))
        summary_table.add_row("Technologies", str(len(technologies)))
        console.print(summary_table)

        # Technologies
        if technologies:
            console.print(f"\n[bold white]Technologies Detected[/bold white]")
            for tech in sorted(technologies):
                console.print(f"  [cyan]•[/cyan] {tech}")
            findings.append(Finding(
                title="Technology Stack Fingerprinted",
                severity=Severity.INFO,
                description=f"Detected: {', '.join(sorted(technologies))}",
            ))

        # Parameters
        if parameters:
            console.print(f"\n[bold white]Parameters Found ({len(parameters)})[/bold white]")
            for p in sorted(parameters)[:30]:
                console.print(f"  [cyan]•[/cyan] {p}")
            findings.append(Finding(
                title=f"Parameters Discovered: {len(parameters)}",
                severity=Severity.INFO,
                description="URL and form parameters found during crawling",
                evidence=", ".join(sorted(parameters)[:20]),
            ))

        # Sitemap analysis
        if sitemaps:
            findings.append(Finding(
                title=f"Sitemap: {len(sitemaps)} URLs",
                severity=Severity.INFO,
                description="Sitemap.xml was found and contains URL entries",
            ))

        # Robots.txt findings
        if robots_text:
            disallowed = [
                line.split(":", 1)[1].strip()
                for line in robots_text.splitlines()
                if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
            ]
            if disallowed:
                findings.append(Finding(
                    title=f"Robots.txt Disallow Entries: {len(disallowed)}",
                    severity=Severity.INFO,
                    description="robots.txt reveals hidden paths",
                    evidence=", ".join(disallowed[:10]),
                ))

        findings.append(Finding(
            title="Content Discovery Summary",
            severity=Severity.INFO,
            description=f"Internal: {len(internal)}, External: {len(external)}, Forms: {len(forms)}",
        ))

        metadata.update({
            "internal_links": len(internal),
            "external_links": len(external),
            "css_files": len(css),
            "js_files": len(js_files),
            "sitemap_urls": len(sitemaps),
            "technologies": sorted(technologies),
            "parameters": sorted(parameters),
        })

        self.summary(f"Internal: {len(internal)}  |  External: {len(external)}  |  Techs: {len(technologies)}")
        console.print("[green][*] Content discovery completed[/green]\n")

        return self.make_result(target=domain, findings=findings, metadata=metadata)

    async def _discover(
        self, base: str, domain: str, page_limit: int,
        include_subs: bool, depth_limit: int,
    ) -> tuple:
        internal: set[str] = set()
        external: set[str] = set()
        css: set[str] = set()
        js_files: set[str] = set()
        forms: list[tuple[str, list[str]]] = []
        technologies: set[str] = set()
        parameters: set[str] = set()

        # ── Robots.txt + Sitemap (async) ──────────────────────────────
        robots_text = ""
        sitemaps: list[str] = []

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Robots.txt
            try:
                async with session.get(f"{base}/robots.txt") as r:
                    if r.status == 200:
                        robots_text = await r.text()
            except Exception:
                pass

            # Sitemap
            try:
                async with session.get(f"{base}/sitemap.xml") as r:
                    if r.status == 200:
                        text = await r.text()
                        soup = bs4.BeautifulSoup(text, "html.parser")
                        sitemaps = [loc.text for loc in soup.find_all("loc")]
            except Exception:
                pass

            # ── Crawl ─────────────────────────────────────────────────
            q: collections.deque[tuple[str, int]] = collections.deque([(base, 0)])
            seen: set[str] = {base}

            while q and len(seen) <= page_limit:
                url, depth = q.popleft()
                try:
                    async with session.get(url, allow_redirects=True) as r:
                        if r.status != 200:
                            continue
                        ct = r.headers.get("content-type", "")
                        if "html" not in ct:
                            continue
                        html = await r.text(errors="ignore")
                except Exception:
                    continue

                soup = bs4.BeautifulSoup(html, "html.parser")

                # Links
                for tag in soup.find_all("a", href=True):
                    href = urllib.parse.urljoin(url, tag["href"].split("#")[0])
                    if href in seen:
                        continue
                    parsed = urllib.parse.urlparse(href)
                    if self._same_scope(base, href, include_subs):
                        internal.add(href)
                        if depth < depth_limit and len(seen) < page_limit:
                            seen.add(href)
                            q.append((href, depth + 1))
                        # Extract URL parameters
                        if parsed.query:
                            for param in urllib.parse.parse_qs(parsed.query):
                                parameters.add(param)
                    else:
                        external.add(href)

                # CSS/JS
                for link in soup.find_all("link", href=True):
                    if link.get("rel") == ["stylesheet"]:
                        css.add(urllib.parse.urljoin(url, link["href"]))
                for script in soup.find_all("script", src=True):
                    js_files.add(urllib.parse.urljoin(url, script["src"]))

                # Forms
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    abs_action = urllib.parse.urljoin(url, action) if action else url
                    inputs = [
                        inp.get("name", "")
                        for inp in form.find_all(["input", "select", "textarea"])
                        if inp.get("name")
                    ]
                    if inputs:
                        forms.append((abs_action, inputs))
                        parameters.update(inputs)

                # Technology fingerprinting
                self._detect_tech(html, str(dict(r.headers)), technologies)

        return internal, external, css, js_files, robots_text, sitemaps, forms, technologies, parameters

    @staticmethod
    def _same_scope(base: str, url: str, include_subs: bool) -> bool:
        base_netloc = urllib.parse.urlparse(base).netloc
        url_netloc = urllib.parse.urlparse(url).netloc
        if include_subs:
            return base_netloc.split(".")[-2:] == url_netloc.split(".")[-2:]
        return base_netloc == url_netloc

    @staticmethod
    def _detect_tech(html: str, headers_str: str, techs: set[str]) -> None:
        signatures = {
            "WordPress": ["wp-content", "wp-includes", "wp-json"],
            "jQuery": ["jquery.min.js", "jQuery"],
            "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
            "React": ["react.production.min.js", "__REACT", "react-root"],
            "Angular": ["ng-version", "angular.min.js"],
            "Vue.js": ["vue.min.js", "v-cloak", "__vue__"],
            "Next.js": ["_next/", "__NEXT_DATA__"],
            "Nuxt.js": ["__nuxt", "_nuxt/"],
            "Tailwind CSS": ["tailwindcss"],
            "Google Analytics": ["google-analytics.com", "gtag"],
            "Google Tag Manager": ["googletagmanager.com"],
            "Cloudflare": ["cf-ray", "cloudflare"],
            "Nginx": ["nginx"],
            "Apache": ["apache"],
            "PHP": ["x-powered-by: php", ".php"],
            "ASP.NET": ["__VIEWSTATE", "asp.net"],
        }
        combined = html + headers_str
        for tech, sigs in signatures.items():
            if any(sig.lower() in combined.lower() for sig in sigs):
                techs.add(tech)


# ── Backward-compatible entry points ────────────────────────────────────────

def main(target):
    instance = ContentDiscovery()
    instance.start_time = time.time()
    instance.run(target, 1, {})


if __name__ == "__main__":
    ContentDiscovery.entrypoint()
