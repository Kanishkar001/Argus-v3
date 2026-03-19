"""
argus.utils.report_generator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Enhanced report generation.

Improvements:
  •  Accepts both legacy ``Dict[str, str]`` and new ``ModuleResult`` objects
  •  Cross-module finding correlation
  •  Severity aggregation
  •  SARIF-format output for CI/CD integration
  •  JSON reports now include structured findings
"""
from __future__ import annotations

import csv
import datetime
import json
import os
import re
from typing import Any, Dict, List

from colorama import Fore

from argus.config import settings
from argus.utils.util import clean_domain_input


def safe_filename(s: str, max_length: int = 255) -> str:
    s = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', s)
    return s[:max_length]


def ensure_results_directory(domain: str) -> str:
    results_dir = os.path.join(os.getcwd(), settings.RESULTS_DIR, domain)
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    return results_dir


def generate_base_filename(domain: str, modules_used: List[str]) -> str:
    domain = clean_domain_input(domain)
    sanitized_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    if len(modules_used) == 1:
        module_part = modules_used[0]
    elif len(modules_used) == 0:
        module_part = "scan"
    else:
        module_part = f"multi_{len(modules_used)}mods"

    base_filename = f"{sanitized_domain}_{module_part}_{timestamp}"
    return safe_filename(base_filename)


# ── Legacy report generators (backward-compat) ──────────────────────────────

def generate_txt_report(data: Dict[str, str], base_filename: str, results_dir: str) -> None:
    txt_file_path = os.path.join(results_dir, f"{base_filename}.txt")
    try:
        with open(txt_file_path, 'w', encoding='utf-8') as txt_file:
            for module_name, output in data.items():
                txt_file.write(f"=== {module_name} ===\n")
                txt_file.write(f"{output}\n\n")
        print(Fore.GREEN + f"TXT report: {os.path.relpath(txt_file_path)}")
    except Exception as e:
        print(Fore.RED + f"Error generating TXT report: {e}")


def generate_csv_report(data: Dict[str, str], base_filename: str, results_dir: str) -> None:
    csv_file_path = os.path.join(results_dir, f"{base_filename}.csv")
    try:
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Module", "Output"])
            for module_name, output in data.items():
                clean_output = output.replace('\n', ' | ').replace('\r', '')
                writer.writerow([module_name, clean_output])
        print(Fore.GREEN + f"CSV report: {os.path.relpath(csv_file_path)}")
    except Exception as e:
        print(Fore.RED + f"Error generating CSV report: {e}")


def generate_json_report(
    data: Dict[str, str],
    base_filename: str,
    results_dir: str,
    domain: str,
    modules_used: List[str],
    module_results: list | None = None,
) -> None:
    json_file_path = os.path.join(results_dir, f"{base_filename}.json")

    payload: dict[str, Any] = {
        "meta": {
            "target": domain,
            "modules": modules_used,
            "timestamp": datetime.datetime.now().isoformat(),
            "argus_version": settings.VERSION,
        },
    }

    # If we have structured ModuleResult objects, use them
    if module_results:
        from argus.core.models import ModuleResult as MR
        payload["results"] = [
            r.to_dict() for r in module_results if isinstance(r, MR)
        ]

        # Cross-module finding aggregation
        all_findings = []
        for r in module_results:
            if isinstance(r, MR):
                for f in r.findings:
                    all_findings.append(f.to_dict())

        severity_counts: dict[str, int] = {}
        for f in all_findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        payload["summary"] = {
            "total_modules": len(module_results),
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
            "total_elapsed": sum(
                r.elapsed_seconds for r in module_results if isinstance(r, MR)
            ),
        }
    else:
        # Legacy text-based results
        payload["results"] = {
            module_name: output.strip().splitlines()
            for module_name, output in data.items()
        }

    try:
        with open(json_file_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
        print(Fore.GREEN + f"JSON report: {os.path.relpath(json_file_path)}")
    except Exception as e:
        print(Fore.RED + f"Error generating JSON report: {e}")


def generate_sarif_report(
    module_results: list,
    base_filename: str,
    results_dir: str,
    domain: str,
) -> None:
    """Generate SARIF-format report for CI/CD integration (GitHub Code Scanning)."""
    from argus.core.models import ModuleResult as MR

    sarif_file = os.path.join(results_dir, f"{base_filename}.sarif")

    sarif_severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
        "ERROR": "error",
    }

    rules = []
    results_list = []
    rule_ids: set[str] = set()

    for mr in module_results:
        if not isinstance(mr, MR):
            continue
        for finding in mr.findings:
            rule_id = re.sub(r'[^a-zA-Z0-9_-]', '_', finding.title.lower())[:64]
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": sarif_severity_map.get(finding.severity.value, "note"),
                    },
                    "helpUri": "",
                })

            results_list.append({
                "ruleId": rule_id,
                "level": sarif_severity_map.get(finding.severity.value, "note"),
                "message": {
                    "text": f"{finding.description}\n{finding.evidence}" if finding.evidence else finding.description,
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": domain,
                        },
                    },
                }],
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Argus",
                    "version": settings.VERSION,
                    "informationUri": "https://github.com/Argus",
                    "rules": rules,
                },
            },
            "results": results_list,
        }],
    }

    try:
        with open(sarif_file, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
        print(Fore.GREEN + f"SARIF report: {os.path.relpath(sarif_file)}")
    except Exception as e:
        print(Fore.RED + f"Error generating SARIF report: {e}")


# ── Main entry point ────────────────────────────────────────────────────────

def generate_report(
    data: Dict[str, str],
    domain: str,
    modules_used: List[str],
    module_results: list | None = None,
) -> None:
    """
    Generate all configured report formats.

    Args:
        data: Legacy text output dict (module_name → text).
        domain: Target domain.
        modules_used: List of module IDs/names.
        module_results: Optional list of ``ModuleResult`` objects for structured reports.
    """
    try:
        base_filename = generate_base_filename(domain, modules_used)
        results_dir = ensure_results_directory(clean_domain_input(domain))

        if settings.EXPORT_SETTINGS.get("enable_txt_export", True):
            generate_txt_report(data, base_filename, results_dir)

        if settings.EXPORT_SETTINGS.get("enable_csv_export", False):
            generate_csv_report(data, base_filename, results_dir)

        if settings.EXPORT_SETTINGS.get("enable_json_export", False):
            generate_json_report(
                data, base_filename, results_dir, domain, modules_used,
                module_results=module_results,
            )

        # SARIF generation (when structured results available)
        if module_results:
            generate_sarif_report(module_results, base_filename, results_dir, domain)

    except Exception as e:
        print(Fore.RED + f"Error generating report: {e}")
