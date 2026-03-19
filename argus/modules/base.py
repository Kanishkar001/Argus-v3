"""
argus.modules.base
~~~~~~~~~~~~~~~~~~
Base class for all Argus modules. Provides a consistent interface,
shared utilities, and graceful error handling.
"""
from __future__ import annotations

import json
import os
import sys
import time
from abc import ABC, abstractmethod
from typing import Any

from rich.console import Console
from rich.panel import Panel

from argus.config.settings import DEFAULT_TIMEOUT, HEADERS
from argus.utils.util import clean_domain_input

console = Console()


class ArgusModule(ABC):
    """
    Inherit from this class when creating a new Argus module.

    Subclasses must implement:
        run(self, target: str, threads: int, opts: dict) -> None

    Usage as a script entry point (all modules follow this pattern):
        if __name__ == "__main__":
            ArgusModule.entrypoint(MyModule)
    """

    #: Human-readable module name (shown in banners)
    name: str = "Unnamed Module"

    #: One-liner description
    description: str = ""

    #: Default request timeout in seconds
    timeout: int = DEFAULT_TIMEOUT

    #: Shared session headers
    headers: dict = HEADERS

    def __init__(self) -> None:
        self.console = Console()
        self.start_time: float = 0.0

    # ── Public interface ──────────────────────────────────────────────────

    @abstractmethod
    def run(self, target: str, threads: int, opts: dict) -> None:
        """Execute the module against *target*."""

    def banner(self) -> None:
        """Print a styled module banner."""
        bar = "=" * 44
        self.console.print(f"[cyan]{bar}")
        self.console.print(f"[cyan]         Argus - {self.name}")
        self.console.print(f"[cyan]{bar}\n")

    def summary(self, extra: str = "") -> None:
        """Print elapsed time summary panel."""
        elapsed = time.time() - self.start_time
        msg = f"Elapsed: {elapsed:.2f}s"
        if extra:
            msg = f"{extra}  |  {msg}"
        self.console.print(Panel(msg, title="Summary", style="bold white"))

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def clean(target: str) -> str:
        return clean_domain_input(target)

    @staticmethod
    def no_api_key(name: str) -> None:
        """Print a warning and return (not exit) when an API key is missing."""
        console.print(
            f"[bold yellow][!] {name} API key not set. "
            "Configure it with: export {name}=your_key_here[/bold yellow]"
        )

    # ── Script entry point ────────────────────────────────────────────────

    @classmethod
    def entrypoint(cls) -> None:
        """
        Standard CLI entry point used by the runner.
        Reads sys.argv: target [threads] [opts_json]
        """
        tgt = sys.argv[1] if len(sys.argv) > 1 else ""
        thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
        opts: dict[str, Any] = {}
        if len(sys.argv) > 3:
            try:
                opts = json.loads(sys.argv[3])
            except json.JSONDecodeError:
                pass

        if not tgt:
            console.print("[bold red][!] No target provided.[/bold red]")
            sys.exit(1)

        instance = cls()
        instance.start_time = time.time()
        try:
            instance.run(tgt, thr, opts)
        except KeyboardInterrupt:
            console.print("\n[bold red][!] Interrupted.[/bold red]")
            sys.exit(0)
        except Exception as exc:
            console.print(f"[bold red][!] Unhandled error: {exc}[/bold red]")
            sys.exit(1)