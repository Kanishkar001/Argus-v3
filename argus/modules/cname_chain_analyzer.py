"""
argus.modules.cname_chain_analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Traces the full CNAME delegation chain for a domain, detects dangling
CNAMEs (potential subdomain takeover), and measures per-hop latency.
"""
from __future__ import annotations

import sys
import time
from typing import Optional

import dns.resolver
import dns.exception
import requests
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.modules.base import ArgusModule
from argus.utils.util import clean_domain_input

console = Console()

TAKEOVER_SIGNATURES: dict[str, str] = {
    "amazonaws.com":              "AWS S3 / Elastic Beanstalk",
    "azurewebsites.net":          "Azure Web Apps",
    "cloudfront.net":             "AWS CloudFront",
    "github.io":                  "GitHub Pages",
    "fastly.net":                 "Fastly",
    "herokudns.com":              "Heroku",
    "shopify.com":                "Shopify",
    "squarespace.com":            "Squarespace",
    "statuspage.io":              "Statuspage",
    "surge.sh":                   "Surge.sh",
    "netlify.app":                "Netlify",
    "netlify.com":                "Netlify",
    "readthedocs.io":             "Read the Docs",
    "zendesk.com":                "Zendesk",
    "helpscoutdocs.com":          "HelpScout",
    "ghost.io":                   "Ghost",
    "webflow.io":                 "Webflow",
    "vercel.app":                 "Vercel",
    "fly.dev":                    "Fly.io",
    "render.com":                 "Render",
}

NXDOMAIN_FINGERPRINTS = [
    "NoSuchBucket",
    "No such app",
    "There is no app",
    "Repository not found",
    "404 Not Found",
    "The resource you are looking for",
    "Unrecognized domain",
    "doesn't exist",
    "Project not found",
    "This site can't be reached",
]


def resolve_cname(domain: str, resolver: dns.resolver.Resolver) -> Optional[str]:
    try:
        ans = resolver.resolve(domain, "CNAME")
        return str(ans[0].target).rstrip(".")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return None


def resolves_to_ip(domain: str, resolver: dns.resolver.Resolver) -> bool:
    try:
        resolver.resolve(domain, "A")
        return True
    except Exception:
        return False


def check_dangling(domain: str, timeout: int) -> Optional[str]:
    """Return fingerprint text if the CNAME target looks unclaimed, else None."""
    try:
        url = f"http://{domain}"
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        body = r.text[:4000]
        for fp in NXDOMAIN_FINGERPRINTS:
            if fp.lower() in body.lower():
                return fp
        return None
    except Exception:
        return None


class CnameChainAnalyzer(ArgusModule):
    name = "CNAME Chain Analyzer"
    description = "Trace CNAME delegation chains and detect dangling / takeover risks"

    def run(self, target: str, threads: int, opts: dict) -> None:
        self.banner()
        domain = self.clean(target)
        timeout = int(opts.get("timeout", self.timeout))
        max_hops = int(opts.get("depth", 10))

        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = float(timeout)

        console.print(f"[cyan][*] Tracing CNAME chain for: [bold]{domain}[/bold][/cyan]\n")

        chain: list[dict] = []
        current = domain
        seen: set[str] = set()

        for hop in range(1, max_hops + 1):
            if current in seen:
                console.print("[yellow][!] CNAME loop detected![/yellow]")
                break
            seen.add(current)

            t0 = time.time()
            cname_target = resolve_cname(current, resolver)
            latency_ms = (time.time() - t0) * 1000

            if cname_target is None:
                # End of chain — check if current resolves to an IP
                resolves = resolves_to_ip(current, resolver)
                chain.append({
                    "hop":       hop,
                    "domain":    current,
                    "points_to": "(terminal)",
                    "latency":   f"{latency_ms:.1f} ms",
                    "resolves":  "✓ A record" if resolves else "✗ No A record",
                    "risk":      "",
                    "provider":  "",
                })
                break

            # Detect known cloud/SaaS providers
            provider = next(
                (name for suffix, name in TAKEOVER_SIGNATURES.items()
                 if cname_target.endswith(suffix)),
                "",
            )

            # Assess takeover risk
            target_resolves = resolves_to_ip(cname_target, resolver)
            if not target_resolves and provider:
                risk = "HIGH — possible takeover"
                dangle_fp = check_dangling(cname_target, timeout)
                if dangle_fp:
                    risk = f"CRITICAL — dangling: '{dangle_fp}'"
            elif not target_resolves:
                risk = "WARN — target NXDOMAIN"
            else:
                risk = ""

            chain.append({
                "hop":       hop,
                "domain":    current,
                "points_to": cname_target,
                "latency":   f"{latency_ms:.1f} ms",
                "resolves":  "✓" if target_resolves else "✗",
                "risk":      risk,
                "provider":  provider,
            })

            current = cname_target

        # ── Display ────────────────────────────────────────────────────────
        if not chain:
            console.print(Panel("[yellow]No CNAME records found for this domain.[/yellow]",
                                title="Result", style="yellow"))
            self.summary()
            return

        table = Table(
            title=f"CNAME Chain — {domain} ({len(chain)} hop(s))",
            header_style="bold magenta",
            box=box.MINIMAL_HEAVY_HEAD,
        )
        table.add_column("#",         style="dim",          width=3)
        table.add_column("Domain",    style="cyan",         overflow="fold")
        table.add_column("Points To", style="white",        overflow="fold")
        table.add_column("Latency",   style="dim",          width=10)
        table.add_column("Resolves",  style="green",        width=12)
        table.add_column("Provider",  style="blue",         width=18)
        table.add_column("Risk",      style="bold red",     overflow="fold")

        for entry in chain:
            risk_style = (
                "bold red"    if "CRITICAL" in entry["risk"] else
                "bold yellow" if "HIGH" in entry["risk"] or "WARN" in entry["risk"] else
                "green"
            )
            table.add_row(
                str(entry["hop"]),
                entry["domain"],
                entry["points_to"],
                entry["latency"],
                entry["resolves"],
                entry["provider"],
                entry["risk"],
                style=risk_style if entry["risk"] else None,
            )

        console.print(table)

        # Summary findings
        critical = [e for e in chain if "CRITICAL" in e["risk"]]
        high     = [e for e in chain if "HIGH" in e["risk"]]
        if critical:
            console.print(f"\n[bold red][!] {len(critical)} CRITICAL takeover risk(s) detected![/bold red]")
        elif high:
            console.print(f"\n[bold yellow][!] {len(high)} potential takeover risk(s). Verify manually.[/bold yellow]")
        else:
            console.print("\n[green][+] No dangling CNAME targets detected.[/green]")

        self.summary(f"Hops: {len(chain)}")
        console.print("[green][*] CNAME chain analysis complete[/green]\n")


if __name__ == "__main__":
    CnameChainAnalyzer.entrypoint()
