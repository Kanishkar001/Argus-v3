"""
argus.modules.whois_lookup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Pure Python WHOIS lookup with RDAP fallback.

Improvements:
  • Removed system dependency on `whois` CLI binary
  • Uses Python `whois` library for cross-platform support
  • RDAP fallback for modern registry data
  • Structured field parsing (registrar, dates, nameservers)
  • Domain age and registration analysis
  • Registrar abuse contact extraction
  • Inherits ArgusModule → structured ModuleResult
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import requests
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.modules.base import ArgusModule, retry
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT
from argus.utils.util import clean_domain_input

console = Console()


# ── RDAP endpoints ───────────────────────────────────────────────────────────
RDAP_BOOTSTRAP = "https://rdap.org/domain/"


class WhoisLookup(ArgusModule):
    name = "WHOIS Lookup"
    description = "Domain registration data via Python WHOIS library + RDAP fallback"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        domain = self.clean(target)
        timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))

        console.print(f"[cyan][*] Target: [bold]{domain}[/bold][/cyan]\n")

        findings: list[Finding] = []
        metadata: dict[str, Any] = {"domain": domain}
        whois_data: dict[str, Any] = {}

        # ── 1. Python WHOIS lookup ────────────────────────────────────
        console.print("[white][*] Performing WHOIS lookup...[/white]")
        try:
            import whois as python_whois
            w = python_whois.whois(domain)
            if w and w.domain_name:
                whois_data = self._parse_whois(w)
                console.print("[green]    WHOIS data retrieved successfully[/green]")
            else:
                console.print("[yellow]    WHOIS returned empty data, trying RDAP...[/yellow]")
        except ImportError:
            console.print("[yellow]    python-whois not installed, trying RDAP...[/yellow]")
        except Exception as exc:
            self.logger.warning("WHOIS lookup failed: %s", exc)
            console.print(f"[yellow]    WHOIS failed: {exc}, trying RDAP...[/yellow]")

        # ── 2. RDAP fallback ──────────────────────────────────────────
        if not whois_data:
            console.print("[white][*] Querying RDAP...[/white]")
            rdap_data = self._rdap_lookup(domain, timeout)
            if rdap_data:
                whois_data = rdap_data
                console.print("[green]    RDAP data retrieved successfully[/green]")
            else:
                console.print("[red]    RDAP lookup also failed[/red]")
                return self.make_result(target=domain, findings=[Finding(
                    title="WHOIS/RDAP Lookup Failed",
                    severity=Severity.ERROR,
                    description=f"Could not retrieve registration data for {domain}",
                )])

        # ── 3. Display data ───────────────────────────────────────────
        table = Table(
            title=f"Domain Registration — {domain}",
            header_style="bold magenta",
            box=box.ROUNDED,
        )
        table.add_column("Field", style="cyan", min_width=20)
        table.add_column("Value", style="green", overflow="fold")

        display_order = [
            "domain_name", "registrar", "creation_date", "expiration_date",
            "updated_date", "name_servers", "status", "registrant_name",
            "registrant_org", "registrant_country", "admin_email",
            "abuse_email", "dnssec", "domain_age_days",
        ]
        for key in display_order:
            if key in whois_data and whois_data[key]:
                val = whois_data[key]
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                table.add_row(key.replace("_", " ").title(), str(val))

        console.print(table)
        metadata.update(whois_data)

        # ── 4. Findings ───────────────────────────────────────────────

        # Domain age
        age_days = whois_data.get("domain_age_days")
        if age_days is not None:
            if age_days < 30:
                findings.append(Finding(
                    title="Newly Registered Domain",
                    severity=Severity.MEDIUM,
                    description=f"Domain was registered only {age_days} days ago",
                    remediation="Newly registered domains are more likely to be malicious",
                ))
            elif age_days < 365:
                findings.append(Finding(
                    title="Young Domain",
                    severity=Severity.LOW,
                    description=f"Domain is {age_days} days old (< 1 year)",
                ))

        # Expiration
        exp_date = whois_data.get("expiration_date")
        if exp_date and isinstance(exp_date, datetime):
            days_until = (exp_date.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            if days_until < 0:
                findings.append(Finding(
                    title="Domain Registration Expired",
                    severity=Severity.HIGH,
                    description=f"Domain expired {abs(days_until)} days ago",
                ))
            elif days_until < 30:
                findings.append(Finding(
                    title="Domain Expiring Soon",
                    severity=Severity.MEDIUM,
                    description=f"Domain expires in {days_until} days",
                    remediation="Renew the domain registration",
                ))

        # Privacy protection
        registrant = whois_data.get("registrant_name", "")
        if registrant and any(
            kw in str(registrant).lower()
            for kw in ["privacy", "protected", "redacted", "withheld", "whoisguard"]
        ):
            findings.append(Finding(
                title="WHOIS Privacy Protection Active",
                severity=Severity.INFO,
                description="Domain uses WHOIS privacy/proxy service",
            ))

        # DNSSEC
        dnssec = whois_data.get("dnssec", "")
        if dnssec and "unsigned" in str(dnssec).lower():
            findings.append(Finding(
                title="DNSSEC Not Configured",
                severity=Severity.LOW,
                description="Domain does not have DNSSEC enabled",
                remediation="Enable DNSSEC for DNS integrity protection",
            ))

        findings.append(Finding(
            title="WHOIS Lookup Summary",
            severity=Severity.INFO,
            description=f"Registration data retrieved for {domain}",
        ))

        self.summary(f"Registrar: {whois_data.get('registrar', 'N/A')}")
        console.print("[green][*] WHOIS lookup completed[/green]\n")

        return self.make_result(target=domain, findings=findings, metadata=metadata)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_whois(w: Any) -> dict[str, Any]:
        """Parse python-whois result into a clean dict."""
        data: dict[str, Any] = {}

        def _first(val: Any) -> Any:
            if isinstance(val, list):
                return val[0] if val else None
            return val

        data["domain_name"] = _first(w.domain_name)
        data["registrar"] = w.registrar
        data["creation_date"] = _first(w.creation_date)
        data["expiration_date"] = _first(w.expiration_date)
        data["updated_date"] = _first(w.updated_date)
        data["name_servers"] = list(w.name_servers) if w.name_servers else []
        data["status"] = list(w.status) if w.status else []
        data["dnssec"] = getattr(w, "dnssec", "")

        # Registrant info
        data["registrant_name"] = getattr(w, "name", "")
        data["registrant_org"] = getattr(w, "org", "")
        data["registrant_country"] = getattr(w, "country", "")
        data["admin_email"] = getattr(w, "emails", "")

        # Domain age
        creation = _first(w.creation_date)
        if creation and isinstance(creation, datetime):
            data["domain_age_days"] = (datetime.now() - creation).days

        return data

    @retry(max_attempts=2, delay=2.0, exceptions=(requests.RequestException,))
    def _rdap_lookup(self, domain: str, timeout: int) -> dict[str, Any] | None:
        """Fallback RDAP lookup."""
        try:
            resp = self.session.get(f"{RDAP_BOOTSTRAP}{domain}", timeout=timeout)
            if resp.status_code != 200:
                return None
            data = resp.json()
            result: dict[str, Any] = {}
            result["domain_name"] = data.get("ldhName", domain)
            result["status"] = data.get("status", [])

            # Events (creation, expiration, etc.)
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date_str = event.get("eventDate", "")
                if action == "registration" and date_str:
                    try:
                        result["creation_date"] = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    except Exception:
                        result["creation_date"] = date_str
                elif action == "expiration" and date_str:
                    try:
                        result["expiration_date"] = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    except Exception:
                        result["expiration_date"] = date_str
                elif action == "last changed" and date_str:
                    result["updated_date"] = date_str

            # Registrar from entities
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [None, []])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn" and len(field) > 3:
                                result["registrar"] = field[3]
                    # Look for abuse contact
                    for sub_entity in entity.get("entities", []):
                        if "abuse" in sub_entity.get("roles", []):
                            sub_vcard = sub_entity.get("vcardArray", [None, []])
                            if len(sub_vcard) > 1:
                                for f in sub_vcard[1]:
                                    if f[0] == "email" and len(f) > 3:
                                        result["abuse_email"] = f[3]

            # Nameservers
            ns_list = []
            for ns in data.get("nameservers", []):
                ns_list.append(ns.get("ldhName", ""))
            result["name_servers"] = ns_list

            # Domain age
            if "creation_date" in result and isinstance(result["creation_date"], datetime):
                result["domain_age_days"] = (
                    datetime.now(timezone.utc) - result["creation_date"]
                ).days

            return result
        except Exception as exc:
            self.logger.warning("RDAP lookup failed: %s", exc)
            return None


# ── Backward-compatible entry points ────────────────────────────────────────

def main(target):
    instance = WhoisLookup()
    instance.start_time = time.time()
    instance.run(target, 1, {})


if __name__ == "__main__":
    WhoisLookup.entrypoint()
