"""
argus.core.runner
~~~~~~~~~~~~~~~~~~
Module execution engine.

Key improvements over the original:
  •  **In-process execution**: imports modules directly and calls
     ``run()`` without spawning a subprocess.  ~5× faster.
  •  **Subprocess fallback**: for isolation or when a module can't be
     imported, falls back to ``subprocess.Popen``.
  •  **Parallel execution**: ``concurrent.futures.ThreadPoolExecutor``
     runs multiple modules concurrently.
  •  **Per-module timeout**: configurable via settings or opts.
  •  **Structured output**: returns ``ModuleResult`` objects.
"""
from __future__ import annotations

import contextlib
import importlib
import json
import logging
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import Any, Dict, List, Tuple

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from argus.config.settings import DEFAULT_TIMEOUT
from argus.core.catalog_cache import tools_mapping
from argus.core.models import Finding, ModuleResult, Severity
from argus.utils.report_generator import generate_report
from argus.utils.util import clean_domain_input

logger = logging.getLogger("argus.core.runner")
console = Console()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "modules")

# Default per-module timeout (seconds).  0 = no timeout.
MODULE_TIMEOUT = 120


# ── In-process execution ────────────────────────────────────────────────────

def _run_module_inprocess(
    module_id: str,
    target: str,
    threads: int,
    opts: dict[str, Any],
    timeout: float = MODULE_TIMEOUT,
) -> ModuleResult:
    """Import a module and call its ``run()`` / ``entrypoint()`` in-process."""
    mod_name = os.path.splitext(module_id)[0] if module_id.endswith(".py") else module_id
    fqn = f"argus.modules.{mod_name}"

    try:
        mod = importlib.import_module(fqn)
    except Exception as exc:
        logger.warning("Could not import %s: %s – falling back to subprocess", fqn, exc)
        return _run_module_subprocess(module_id, target, threads, opts)

    # Strategy 1: Module has a class inheriting ArgusModule
    from argus.modules.base import ArgusModule
    for attr_name in dir(mod):
        attr = getattr(mod, attr_name)
        if (
            isinstance(attr, type)
            and issubclass(attr, ArgusModule)
            and attr is not ArgusModule
        ):
            instance = attr()
            instance.start_time = time.time()
            try:
                result = instance.run(clean_domain_input(target), threads, opts)
                if isinstance(result, ModuleResult):
                    return result
                # Legacy module returned None – wrap
                return ModuleResult(
                    module_name=attr.name,
                    target=target,
                    elapsed_seconds=time.time() - instance.start_time,
                )
            except Exception as exc:
                logger.exception("Module %s raised: %s", mod_name, exc)
                return ModuleResult(
                    module_name=attr.name,
                    target=target,
                    severity=Severity.ERROR,
                    elapsed_seconds=time.time() - instance.start_time,
                    findings=[Finding(
                        title="Module Error",
                        severity=Severity.ERROR,
                        description=str(exc),
                    )],
                )

    # Strategy 2: Module has a top-level ``run(target, threads, opts)`` function
    if hasattr(mod, "run") and callable(mod.run):
        start = time.time()
        try:
            # Capture stdout
            from io import StringIO
            buf = StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                mod.run(clean_domain_input(target), threads, opts)
            finally:
                sys.stdout = old_stdout
            raw = buf.getvalue()
            return ModuleResult(
                module_name=mod_name,
                target=target,
                elapsed_seconds=time.time() - start,
                raw_output=raw,
            )
        except Exception as exc:
            logger.exception("Module %s.run() raised: %s", mod_name, exc)
            return ModuleResult(
                module_name=mod_name,
                target=target,
                severity=Severity.ERROR,
                elapsed_seconds=time.time() - start,
                findings=[Finding(
                    title="Module Error",
                    severity=Severity.ERROR,
                    description=str(exc),
                )],
            )

    # Strategy 3: Module has a ``main(target)`` function (legacy)
    if hasattr(mod, "main") and callable(mod.main):
        start = time.time()
        try:
            from io import StringIO
            buf = StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                mod.main(clean_domain_input(target))
            finally:
                sys.stdout = old_stdout
            raw = buf.getvalue()
            return ModuleResult(
                module_name=mod_name,
                target=target,
                elapsed_seconds=time.time() - start,
                raw_output=raw,
            )
        except Exception as exc:
            logger.exception("Module %s.main() raised: %s", mod_name, exc)
            return ModuleResult(
                module_name=mod_name,
                target=target,
                severity=Severity.ERROR,
                elapsed_seconds=time.time() - start,
                findings=[Finding(
                    title="Module Error",
                    severity=Severity.ERROR,
                    description=str(exc),
                )],
            )

    # No callable found – fall back to subprocess
    logger.info("No callable entry found in %s – using subprocess", fqn)
    return _run_module_subprocess(module_id, target, threads, opts)


# ── Subprocess fallback ─────────────────────────────────────────────────────

def _run_module_subprocess(
    script_name: str,
    target: str,
    threads: int,
    opts: dict[str, Any] | None = None,
) -> ModuleResult:
    """Execute a module as a subprocess (isolation mode)."""
    mod = os.path.splitext(script_name)[0] if script_name.endswith(".py") else script_name
    script_path = os.path.join(MODULES_DIR, f"{mod}.py")

    if not os.path.isfile(script_path):
        console.print(f"[bold red]Missing script {script_name}[/bold red]")
        return ModuleResult(
            module_name=mod,
            target=target,
            severity=Severity.ERROR,
            findings=[Finding(
                title="Missing Module",
                severity=Severity.ERROR,
                description=f"Script file not found: {script_name}",
            )],
        )

    cmd = [
        sys.executable, "-m", f"argus.modules.{mod}",
        clean_domain_input(target), str(threads),
    ]
    if opts:
        cmd.append(json.dumps(opts))

    start = time.time()
    raw_lines: list[str] = []
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in iter(proc.stdout.readline, ""):
            if not line:
                break
            raw_lines.append(line.rstrip("\n"))
        proc.stdout.close()
        proc.wait(timeout=MODULE_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        logger.warning("Module %s timed out after %ss", mod, MODULE_TIMEOUT)
    except Exception as exc:
        logger.exception("Subprocess execution failed for %s: %s", mod, exc)

    raw = "\n".join(raw_lines)
    elapsed = time.time() - start

    sev = _parse_output_severity(raw)
    return ModuleResult(
        module_name=mod,
        target=target,
        severity=sev,
        elapsed_seconds=elapsed,
        raw_output=raw,
    )


# ── Severity heuristic (for subprocess text output) ─────────────────────────

import re

_SEVERITY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bcritical\b|\bsevere\b|\bexploit\b|\bcompromise\b", re.I), "ALERT"),
    (re.compile(r"\bhigh\b|\balert\b|\bvulnerable\b|\bexpired\b", re.I), "ALERT"),
    (re.compile(r"\bwarn\b|\bwarning\b|\brisk\b|\bexposed\b", re.I), "WARN"),
    (re.compile(r"\bok\b|\bsecure\b|\bvalid\b", re.I), "OK"),
]


def _parse_output_severity(text: str) -> Severity:
    sev = "INFO"
    for rx, label in _SEVERITY_PATTERNS:
        if rx.search(text):
            if label == "ALERT":
                return Severity.HIGH
            if label == "WARN" and sev not in ("ALERT", "WARN"):
                sev = "WARN"
            if label == "OK" and sev == "INFO":
                sev = "OK"
    mapping = {"INFO": Severity.INFO, "WARN": Severity.MEDIUM, "OK": Severity.INFO}
    return mapping.get(sev, Severity.INFO)


# ── Public: single-module execution ─────────────────────────────────────────

def execute_script(
    script_name: str,
    target: str,
    threads: int = 1,
    module_opts: dict | None = None,
    show_status: bool = True,
    quiet: bool = False,
    use_subprocess: bool = False,
) -> str:
    """
    Execute a single module.  Returns raw text output (backward-compat).

    Set ``use_subprocess=True`` to force isolation mode.
    """
    ctx = (
        console.status(f"[bold green]Running {script_name}[/bold green]", spinner="dots")
        if show_status
        else contextlib.nullcontext()
    )
    with ctx:
        if use_subprocess:
            result = _run_module_subprocess(script_name, target, threads, module_opts)
        else:
            result = _run_module_inprocess(script_name, target, threads, module_opts or {})

    # Print output for backward-compat console display
    if result.raw_output and not quiet:
        for line in result.raw_output.splitlines():
            console.print(line)

    return result.raw_output


def execute_module(
    script_name: str,
    target: str,
    threads: int = 1,
    module_opts: dict | None = None,
    use_subprocess: bool = False,
) -> ModuleResult:
    """Execute a module and return structured ``ModuleResult``."""
    if use_subprocess:
        return _run_module_subprocess(script_name, target, threads, module_opts)
    return _run_module_inprocess(script_name, target, threads, module_opts or {})


# ── Public: batch execution ─────────────────────────────────────────────────

def run_modules(
    mod_ids: list[str],
    api_status: dict[str, bool],
    target: str,
    threads: int,
    mode_name: str,
    cli_ctx: Any,
    *,
    parallel: int = 1,
    per_module_timeout: float = MODULE_TIMEOUT,
) -> list[ModuleResult]:
    """
    Run a list of module IDs.

    Args:
        parallel: How many modules to run concurrently (1 = sequential).
        per_module_timeout: Hard timeout per module.

    Returns:
        List of ``ModuleResult`` objects.
    """
    results: list[ModuleResult] = []
    data: dict[str, str] = {}
    runtimes: list[tuple[str, str, float]] = []
    total = len(mod_ids)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.fields[module]}"),
        BarColumn(bar_width=None),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("run", total=total, module="…")

        def _execute_one(mid: str) -> ModuleResult:
            tool = tools_mapping.get(mid)
            script = tool["script"] if tool else f"{mid}.py"
            allow = [
                o.replace("-", "_").lower()
                for o in (tool.get("options_meta") or [])
            ] if tool else []
            merged = (
                _merge_options(
                    cli_ctx.global_option_overrides,
                    cli_ctx.module_options.get(mid),
                    allow,
                )
                if cli_ctx
                else {}
            )
            return _run_module_inprocess(script, target, threads, merged)

        if parallel <= 1:
            # Sequential – existing behaviour
            for mid in mod_ids:
                tool = tools_mapping.get(mid)
                name = tool["name"] if tool else mid
                prog.update(task, module=name)
                result = _execute_one(mid)
                results.append(result)
                if result.raw_output:
                    data[name] = result.raw_output
                runtimes.append((name, result.overall_severity().value, result.elapsed_seconds))
                if cli_ctx:
                    cli_ctx._record_recent(mid)
                prog.advance(task)
        else:
            # Parallel
            with ThreadPoolExecutor(max_workers=parallel) as pool:
                future_to_mid = {
                    pool.submit(_execute_one, mid): mid for mid in mod_ids
                }
                for future in as_completed(future_to_mid):
                    mid = future_to_mid[future]
                    tool = tools_mapping.get(mid)
                    name = tool["name"] if tool else mid
                    prog.update(task, module=name)
                    try:
                        result = future.result(timeout=per_module_timeout)
                    except FuturesTimeout:
                        result = ModuleResult(
                            module_name=name,
                            target=target,
                            severity=Severity.ERROR,
                            findings=[Finding(
                                title="Timeout",
                                severity=Severity.ERROR,
                                description=f"Module timed out after {per_module_timeout}s",
                            )],
                        )
                    except Exception as exc:
                        result = ModuleResult(
                            module_name=name,
                            target=target,
                            severity=Severity.ERROR,
                            findings=[Finding(
                                title="Execution Error",
                                severity=Severity.ERROR,
                                description=str(exc),
                            )],
                        )
                    results.append(result)
                    if result.raw_output:
                        data[name] = result.raw_output
                    runtimes.append((name, result.overall_severity().value, result.elapsed_seconds))
                    if cli_ctx:
                        cli_ctx._record_recent(mid)
                    prog.advance(task)

    # Generate legacy report (backward-compat)
    tag = mode_name if mode_name else "multi"
    generate_report(data, target, [tag])

    if cli_ctx:
        cli_ctx.last_run_outputs = data
        cli_ctx.last_run_runtimes = runtimes

    return results


# ── Internal helpers ─────────────────────────────────────────────────────────

def _merge_options(
    global_over: dict | None,
    module_opts: dict | None,
    allowed: list[str],
) -> dict:
    combined: dict = {}
    if global_over:
        for k, v in global_over.items():
            if k in allowed and k not in combined:
                combined[k] = v
    if module_opts:
        combined.update(module_opts)
    return combined


# ── Backward-compat aliases ─────────────────────────────────────────────────

def parse_output_severity(text: str) -> str:
    """Old API: return text label."""
    return _parse_output_severity(text).value
