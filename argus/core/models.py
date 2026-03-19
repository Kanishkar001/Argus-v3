"""
argus.core.models
~~~~~~~~~~~~~~~~~
Structured data models for standardized module output.
Every module returns a ``ModuleResult`` populated with ``Finding`` objects
so the runner, reporter, and web dashboard all consume identical data.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# Put this BEFORE the class definition
_SEVERITY_ORDER = {
    "CRITICAL": 1,
    "HIGH":     2,
    "MEDIUM":   3,
    "LOW":      4,
    "INFO":     5,
    "ERROR":    6,
}

class Severity(str, Enum):
    """Standardised severity labels, ordered most → least severe."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"
    ERROR    = "ERROR"

    # allow comparison / sorting
    def __lt__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER.get(self.value, 99) < _SEVERITY_ORDER.get(other.value, 99)

    def __le__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER.get(self.value, 99) <= _SEVERITY_ORDER.get(other.value, 99)


@dataclass
class Finding:
    """A single security observation produced by a module."""
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    cve_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve_ids": self.cve_ids,
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class ModuleResult:
    """
    The standard return value for every module's ``run()`` method.
    """
    module_name: str
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    severity: Severity = Severity.INFO
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    raw_output: str = ""  # optional: legacy text output for backward-compat

    # ── Helpers ──────────────────────────────────────────────────────

    def overall_severity(self) -> Severity:
        """Return the most-severe finding severity, or INFO when empty."""
        if not self.findings:
            return Severity.INFO
        return min(f.severity for f in self.findings)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "target": self.target,
            "timestamp": self.timestamp,
            "severity": self.overall_severity().value,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }

    def to_legacy_text(self) -> str:
        """Render a Rich-free plaintext summary (for subprocess fallback)."""
        lines: list[str] = [
            f"=== {self.module_name} ===",
            f"Target: {self.target}",
            f"Severity: {self.overall_severity().value}",
            f"Findings: {len(self.findings)}",
        ]
        for f in self.findings:
            lines.append(f"  [{f.severity.value}] {f.title}: {f.description}")
            if f.evidence:
                lines.append(f"    Evidence: {f.evidence}")
            if f.remediation:
                lines.append(f"    Fix: {f.remediation}")
        lines.append(f"Elapsed: {self.elapsed_seconds:.2f}s")
        return "\n".join(lines)
