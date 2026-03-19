"""
argus.modules.email_spoofing_test
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests whether a domain is vulnerable to email spoofing by checking
SPF, DMARC, DKIM selector presence, MTA-STS, and BIMI records.
Produces a clear risk score with recommendations.
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field

import dns.resolver
import dns.exception
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argus.modules.base import ArgusModule
from argus.utils.util import clean_domain_input

console = Console()


@dataclass
class CheckResult:
    name:   str
    status: str        # PASS / WARN / FAIL / INFO
    detail: str
    score:  int = 0    # positive = good, negative = bad


def check_spf(domain: str, resolver: dns.resolver.Resolver) -> CheckResult:
    try:
        answers = resolver.resolve(domain, "TXT")
        spf_records = [str(r) for r in answers if "v=spf1" in str(r).lower()]
        if not spf_records:
            return CheckResult("SPF Record", "FAIL", "No SPF record found. Domain can be spoofed.", -20)
        spf = spf_records[0]
        if len(spf_records) > 1:
            return CheckResult("SPF Record", "WARN",
                               f"Multiple SPF records ({len(spf_records)}) — only one is valid.", -10)
        if "-all" in spf:
            return CheckResult("SPF Record", "PASS", f"Hard fail (-all) policy. {spf[:80]}", 20)
        if "~all" in spf:
            return CheckResult("SPF Record", "WARN", f"Soft fail (~all) — spoofing may still work. {spf[:80]}", 5)
        if "?all" in spf or "+all" in spf:
            return CheckResult("SPF Record", "FAIL", f"Permissive SPF (?all/+all) — no protection. {spf[:80]}", -15)
        return CheckResult("SPF Record", "WARN", f"SPF present but no explicit 'all' policy. {spf[:80]}", 0)
    except dns.resolver.NXDOMAIN:
        return CheckResult("SPF Record", "FAIL", "Domain does not exist.", -25)
    except dns.exception.DNSException:
        return CheckResult("SPF Record", "WARN", "SPF lookup failed (DNS error).", 0)


def check_dmarc(domain: str, resolver: dns.resolver.Resolver) -> CheckResult:
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = str(r)
            if "v=DMARC1" in txt:
                if "p=reject" in txt:
                    return CheckResult("DMARC", "PASS", f"Reject policy. {txt[:100]}", 25)
                if "p=quarantine" in txt:
                    return CheckResult("DMARC", "WARN", f"Quarantine policy (emails not rejected). {txt[:100]}", 10)
                if "p=none" in txt:
                    return CheckResult("DMARC", "FAIL",
                                       f"p=none — monitoring only, no enforcement. {txt[:100]}", -10)
        return CheckResult("DMARC", "FAIL", "No valid DMARC record found.", -20)
    except dns.resolver.NXDOMAIN:
        return CheckResult("DMARC", "FAIL", "No DMARC record (_dmarc subdomain missing).", -20)
    except dns.exception.DNSException:
        return CheckResult("DMARC", "WARN", "DMARC lookup failed (DNS error).", 0)


def check_dkim(domain: str, resolver: dns.resolver.Resolver) -> list[CheckResult]:
    """Try common DKIM selectors."""
    common_selectors = [
        "default", "google", "k1", "k2", "mail", "email",
        "dkim", "selector1", "selector2", "s1", "s2",
        "mandrill", "sendgrid", "mailchimp", "zoho",
    ]
    found = []
    for sel in common_selectors:
        try:
            resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            found.append(sel)
        except Exception:
            pass

    if found:
        return [CheckResult("DKIM Selectors", "PASS",
                            f"Found selectors: {', '.join(found)}", 15)]
    return [CheckResult("DKIM Selectors", "WARN",
                        "No common DKIM selectors found (may use custom ones).", -5)]


def check_mta_sts(domain: str, resolver: dns.resolver.Resolver) -> CheckResult:
    try:
        resolver.resolve(f"_mta-sts.{domain}", "TXT")
        return CheckResult("MTA-STS", "PASS", "MTA-STS policy present (forces TLS for inbound).", 10)
    except Exception:
        return CheckResult("MTA-STS", "INFO", "No MTA-STS record (optional but recommended).", 0)


def check_bimi(domain: str, resolver: dns.resolver.Resolver) -> CheckResult:
    try:
        answers = resolver.resolve(f"default._bimi.{domain}", "TXT")
        for r in answers:
            if "v=BIMI1" in str(r):
                return CheckResult("BIMI", "INFO", "BIMI logo record present.", 5)
    except Exception:
        pass
    return CheckResult("BIMI", "INFO", "No BIMI record (optional).", 0)


STATUS_STYLE = {
    "PASS": "[bold green]PASS[/bold green]",
    "WARN": "[bold yellow]WARN[/bold yellow]",
    "FAIL": "[bold red]FAIL[/bold red]",
    "INFO": "[dim]INFO[/dim]",
}

RISK_LABELS = {
    range(60, 101):  ("LOW",      "green"),
    range(30,  60):  ("MODERATE", "yellow"),
    range(0,   30):  ("HIGH",     "red"),
    range(-100,  0): ("CRITICAL", "bold red"),
}


def risk_label(score: int) -> tuple[str, str]:
    for r, (label, color) in RISK_LABELS.items():
        if score in r:
            return label, color
    return "CRITICAL", "bold red"


class EmailSpoofingTest(ArgusModule):
    name = "Email Spoofing Test"
    description = "Assess SPF/DMARC/DKIM configuration and email spoofing risk"

    def run(self, target: str, threads: int, opts: dict) -> None:
        self.banner()
        domain = self.clean(target)
        timeout = int(opts.get("timeout", self.timeout))

        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = float(timeout)

        console.print(f"[cyan][*] Checking email security for: [bold]{domain}[/bold][/cyan]\n")

        checks: list[CheckResult] = []
        checks.append(check_spf(domain, resolver))
        checks.append(check_dmarc(domain, resolver))
        checks.extend(check_dkim(domain, resolver))
        checks.append(check_mta_sts(domain, resolver))
        checks.append(check_bimi(domain, resolver))

        # ── Results table ──────────────────────────────────────────────────
        table = Table(
            title=f"Email Security Assessment — {domain}",
            header_style="bold magenta",
            box=box.MINIMAL_HEAVY_HEAD,
        )
        table.add_column("Check",   style="cyan",  no_wrap=True, width=18)
        table.add_column("Status",  width=8)
        table.add_column("Detail",  overflow="fold")

        for c in checks:
            table.add_row(c.name, STATUS_STYLE.get(c.status, c.status), c.detail)

        console.print(table)

        # ── Risk score ─────────────────────────────────────────────────────
        total_score = max(0, min(100, 50 + sum(c.score for c in checks)))
        label, color = risk_label(total_score)

        score_panel = Text()
        score_panel.append(f"Spoofing Risk: ", style="bold white")
        score_panel.append(f"{label} ", style=f"bold {color}")
        score_panel.append(f"(score {total_score}/100)", style="dim")

        console.print()
        console.print(Panel(score_panel, title="Risk Summary", style=color))

        # ── Recommendations ────────────────────────────────────────────────
        recs = []
        for c in checks:
            if c.status == "FAIL":
                if "SPF" in c.name:
                    recs.append("Add an SPF record with '-all' to prevent spoofing.")
                if "DMARC" in c.name:
                    recs.append("Add a DMARC record with 'p=reject' or 'p=quarantine'.")
            if c.status == "WARN":
                if "SPF" in c.name and "~all" in c.detail:
                    recs.append("Upgrade SPF from '~all' (soft fail) to '-all' (hard fail).")
                if "DMARC" in c.name and "p=none" in c.detail:
                    recs.append("Upgrade DMARC from 'p=none' to 'p=quarantine' or 'p=reject'.")

        if recs:
            console.print("\n[bold yellow]Recommendations:[/bold yellow]")
            for i, rec in enumerate(recs, 1):
                console.print(f"  {i}. {rec}")

        self.summary(f"Checks: {len(checks)}")
        console.print("[green][*] Email spoofing test complete[/green]\n")


if __name__ == "__main__":
    EmailSpoofingTest.entrypoint()
