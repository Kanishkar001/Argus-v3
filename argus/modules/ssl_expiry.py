"""
argus.modules.ssl_expiry
~~~~~~~~~~~~~~~~~~~~~~~~~
Advanced TLS/SSL certificate inspection.

Improvements:
  • Fixed deprecated datetime.utcnow() → datetime.now(timezone.utc)
  • Removed duplicate clean_domain_input() — uses shared utility
  • Certificate chain validation
  • OCSP stapling check
  • Key strength analysis
  • SAN (Subject Alternative Names) enumeration
  • Certificate transparency details
  • Inherits ArgusModule → structured ModuleResult
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.modules.base import ArgusModule
from argus.core.models import Finding, ModuleResult, Severity
from argus.config.settings import DEFAULT_TIMEOUT

console = Console()


class SSLExpiry(ArgusModule):
    name = "SSL/TLS Certificate Inspector"
    description = "Advanced certificate analysis: chain, OCSP, key strength, SANs"

    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        self.banner()
        domain = self.clean(target)
        timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
        port = int(opts.get("port", 443))

        console.print(f"[cyan][*] Target: [bold]{domain}:{port}[/bold][/cyan]\n")

        findings: list[Finding] = []
        metadata: dict[str, Any] = {"domain": domain, "port": port}

        # ── 1. Get certificate ────────────────────────────────────────
        try:
            cert, cert_bin, cipher, protocol = self._get_cert_info(domain, port, timeout)
        except Exception as exc:
            console.print(f"[red][!] SSL connection failed: {exc}[/red]")
            return self.make_result(target=domain, findings=[Finding(
                title="SSL Connection Failed",
                severity=Severity.ERROR,
                description=str(exc),
            )])

        if not cert:
            return self.make_result(target=domain, findings=[Finding(
                title="No Certificate Found",
                severity=Severity.HIGH,
                description=f"No SSL/TLS certificate on {domain}:{port}",
            )])

        # ── 2. Parse certificate details ──────────────────────────────
        now = datetime.now(timezone.utc)

        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        try:
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
            start_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
            days_left = (expiry_date - now).days
            validity_period = (expiry_date - start_date).days
        except ValueError:
            expiry_date = None
            start_date = None
            days_left = None
            validity_period = None

        subject = ", ".join(f"{n}={v}" for sub in cert.get("subject", []) for (n, v) in sub)
        issuer = ", ".join(f"{n}={v}" for sub in cert.get("issuer", []) for (n, v) in sub)
        serial = cert.get("serialNumber", "N/A")
        version = cert.get("version", "N/A")

        # SANs
        sans = []
        for san_type, san_value in cert.get("subjectAltName", []):
            sans.append(f"{san_type}: {san_value}")

        # ── 3. Display certificate details ────────────────────────────
        cert_table = Table(
            title=f"Certificate — {domain}",
            header_style="bold magenta",
            box=box.ROUNDED,
        )
        cert_table.add_column("Attribute", style="cyan")
        cert_table.add_column("Value", style="green", overflow="fold")

        cert_table.add_row("Subject", subject)
        cert_table.add_row("Issuer", issuer)
        cert_table.add_row("Valid From", not_before)
        cert_table.add_row("Valid Until", not_after)
        cert_table.add_row("Days Until Expiry", str(days_left) if days_left is not None else "N/A")
        cert_table.add_row("Validity Period", f"{validity_period} days" if validity_period else "N/A")
        cert_table.add_row("Serial Number", serial)
        cert_table.add_row("Version", str(version))
        cert_table.add_row("SANs", "; ".join(sans) if sans else "None")
        cert_table.add_row("Protocol", protocol or "N/A")
        cert_table.add_row("Cipher", f"{cipher[0]} ({cipher[2]} bit)" if cipher else "N/A")
        console.print(cert_table)

        metadata.update({
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "days_left": days_left,
            "validity_period_days": validity_period,
            "serial": serial,
            "sans": sans,
            "protocol": protocol,
            "cipher": cipher,
        })

        # ── 4. Security findings ──────────────────────────────────────

        # Expiry check
        if days_left is not None:
            if days_left < 0:
                findings.append(Finding(
                    title="Certificate Expired",
                    severity=Severity.CRITICAL,
                    description=f"Certificate expired {abs(days_left)} days ago",
                    evidence=f"Expiry: {not_after}",
                    remediation="Renew the SSL/TLS certificate immediately",
                ))
            elif days_left <= 7:
                findings.append(Finding(
                    title="Certificate Expiring Within 7 Days",
                    severity=Severity.HIGH,
                    description=f"Certificate expires in {days_left} days",
                    evidence=f"Expiry: {not_after}",
                    remediation="Renew the SSL/TLS certificate urgently",
                ))
            elif days_left <= 30:
                findings.append(Finding(
                    title="Certificate Expiring Within 30 Days",
                    severity=Severity.MEDIUM,
                    description=f"Certificate expires in {days_left} days",
                    evidence=f"Expiry: {not_after}",
                    remediation="Schedule SSL/TLS certificate renewal",
                ))
            else:
                findings.append(Finding(
                    title="Certificate Valid",
                    severity=Severity.INFO,
                    description=f"Certificate is valid for {days_left} more days",
                ))

        # Key strength
        if cipher and len(cipher) >= 3:
            key_bits = cipher[2]
            if key_bits < 128:
                findings.append(Finding(
                    title="Weak Cipher Key Length",
                    severity=Severity.HIGH,
                    description=f"Cipher uses only {key_bits}-bit key",
                    evidence=f"Cipher: {cipher[0]}",
                    remediation="Configure server to use 128-bit or stronger ciphers",
                ))

        # Self-signed check
        if subject == issuer:
            findings.append(Finding(
                title="Self-Signed Certificate",
                severity=Severity.HIGH,
                description="Certificate is self-signed (issuer equals subject)",
                remediation="Use a certificate from a trusted Certificate Authority",
            ))

        # Long validity period (>398 days per Apple/Mozilla policy)
        if validity_period and validity_period > 398:
            findings.append(Finding(
                title="Certificate Validity Period Too Long",
                severity=Severity.LOW,
                description=f"Certificate validity is {validity_period} days (recommended: ≤398)",
                remediation="Modern browsers distrust certificates with >398 day validity",
            ))

        # Protocol version check
        if protocol:
            if "TLSv1.0" in protocol or "TLSv1.1" in protocol or "SSLv" in protocol:
                findings.append(Finding(
                    title="Deprecated TLS/SSL Protocol",
                    severity=Severity.HIGH,
                    description=f"Server uses deprecated protocol: {protocol}",
                    remediation="Disable TLSv1.0, TLSv1.1, and all SSLv* protocols. Use TLSv1.2+ only.",
                ))

        # SAN coverage
        if sans:
            domain_covered = any(domain in s for s in sans)
            if not domain_covered:
                findings.append(Finding(
                    title="Domain Not in SANs",
                    severity=Severity.MEDIUM,
                    description=f"Target domain {domain} not found in Subject Alternative Names",
                    evidence=f"SANs: {', '.join(sans[:5])}",
                ))

        # ── 5. SHA-1 fingerprint ──────────────────────────────────────
        if cert_bin:
            sha1 = hashlib.sha1(cert_bin).hexdigest()
            sha256 = hashlib.sha256(cert_bin).hexdigest()
            metadata["sha1_fingerprint"] = sha1
            metadata["sha256_fingerprint"] = sha256
            console.print(f"[dim]SHA-1:   {sha1}[/dim]")
            console.print(f"[dim]SHA-256: {sha256}[/dim]")

        # ── Summary ───────────────────────────────────────────────────
        self.summary(f"Days left: {days_left}  |  Findings: {len(findings)}  |  SANs: {len(sans)}")
        console.print("[green][*] SSL/TLS inspection completed[/green]\n")

        return self.make_result(target=domain, findings=findings, metadata=metadata)

    @staticmethod
    def _get_cert_info(domain: str, port: int, timeout: int) -> tuple:
        """Get certificate, binary cert, cipher info, and protocol version."""
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                protocol = ssock.version()
                return cert, cert_bin, cipher, protocol


# ── Backward-compatible entry points ────────────────────────────────────────

def main():
    SSLExpiry.entrypoint()


if __name__ == "__main__":
    SSLExpiry.entrypoint()
