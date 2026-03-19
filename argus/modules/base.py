"""
argus.modules.base
~~~~~~~~~~~~~~~~~~~
Enhanced base class for all Argus modules.

Key improvements over the original:
  •  ``run()`` now returns a ``ModuleResult`` instead of printing to stdout.
  •  Built-in ``requests.Session`` with retry, rate-limiting, and
     configurable timeout.
  •  Structured logging per module (via ``core.logging_config``).
  •  ``entrypoint()`` works both as CLI (reads sys.argv) *and* when
     called in-process (accepts explicit args).
  •  ``retry()`` decorator for flaky network operations.
"""
from __future__ import annotations

import functools
import json
import logging
import os
import sys
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, TypeVar

from rich.console import Console
from rich.panel import Panel

from argus.config.settings import DEFAULT_TIMEOUT, HEADERS
from argus.core.models import Finding, ModuleResult, Severity
from argus.utils.util import clean_domain_input

console = Console()

F = TypeVar("F", bound=Callable[..., Any])


# ── Retry decorator ─────────────────────────────────────────────────────────

def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> Callable[[F], F]:
    """Decorator: retry a function with exponential backoff."""
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: BaseException | None = None
            wait = delay
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_attempts:
                        time.sleep(wait)
                        wait *= backoff
            raise last_exc  # type: ignore[misc]
        return wrapper  # type: ignore[return-value]
    return decorator


class ArgusModule(ABC):
    """
    Inherit from this class when creating a new Argus module.

    Subclasses must implement:
        ``run(self, target: str, threads: int, opts: dict) -> ModuleResult``

    Usage as a script entry point::

        if __name__ == "__main__":
            MyModule.entrypoint()
    """

    #: Human-readable module name (shown in banners / reports)
    name: str = "Unnamed Module"

    #: One-liner description
    description: str = ""

    #: Default request timeout in seconds
    timeout: int = DEFAULT_TIMEOUT

    #: Shared session headers
    headers: dict[str, str] = HEADERS

    def __init__(self) -> None:
        self.console = Console()
        self.start_time: float = 0.0
        self.logger = logging.getLogger(f"argus.modules.{self.__class__.__name__}")

        # Lazy session – created on first access
        self._session: "requests.Session | None" = None

    # ── HTTP Session ─────────────────────────────────────────────────────

    @property
    def session(self) -> "requests.Session":
        """Per-module HTTP session with retry and default headers."""
        if self._session is None:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            retry_strategy = Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
                raise_on_status=False,
            )
            self._session = requests.Session()
            adapter = HTTPAdapter(pool_maxsize=20, max_retries=retry_strategy)
            self._session.mount("https://", adapter)
            self._session.mount("http://", adapter)
            self._session.headers.update(self.headers)
        return self._session

    # ── Public interface ─────────────────────────────────────────────────

    @abstractmethod
    def run(self, target: str, threads: int, opts: dict) -> ModuleResult:
        """Execute the module against *target* and return structured results."""

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

    def make_result(
        self,
        target: str,
        findings: list[Finding] | None = None,
        metadata: dict[str, Any] | None = None,
        raw_output: str = "",
    ) -> ModuleResult:
        """Convenience factory to build a ``ModuleResult`` for this module."""
        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=findings or [],
            metadata=metadata or {},
            elapsed_seconds=time.time() - self.start_time,
            raw_output=raw_output,
        )

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def clean(target: str) -> str:
        return clean_domain_input(target)

    @staticmethod
    def no_api_key(name: str) -> None:
        """Print a warning when an API key is missing."""
        console.print(
            f"[bold yellow][!] {name} API key not set. "
            f"Configure it with: export {name}=your_key_here[/bold yellow]"
        )

    # ── Script entry point ───────────────────────────────────────────────

    @classmethod
    def entrypoint(
        cls,
        target: str | None = None,
        threads: int | None = None,
        opts: dict | None = None,
    ) -> ModuleResult | None:
        """
        Dual-mode entry point.

        • **CLI mode** (no args): reads ``sys.argv`` for target, threads, opts.
        • **In-process mode**: accepts explicit ``target``, ``threads``, ``opts``.

        Returns:
            ``ModuleResult`` or ``None`` on error.
        """
        # Resolve arguments ────────────────────────────────────────────
        if target is None:
            target = sys.argv[1] if len(sys.argv) > 1 else ""
        if threads is None:
            threads = (
                int(sys.argv[2])
                if len(sys.argv) > 2 and sys.argv[2].isdigit()
                else 1
            )
        if opts is None:
            opts = {}
            if len(sys.argv) > 3:
                try:
                    opts = json.loads(sys.argv[3])
                except json.JSONDecodeError:
                    pass

        if not target:
            console.print("[bold red][!] No target provided.[/bold red]")
            if __name__ == "__main__":
                sys.exit(1)
            return None

        instance = cls()
        instance.start_time = time.time()
        try:
            result = instance.run(target, threads, opts)
            return result
        except KeyboardInterrupt:
            console.print("\n[bold red][!] Interrupted.[/bold red]")
            if __name__ == "__main__":
                sys.exit(0)
            return None
        except Exception as exc:
            instance.logger.exception("Unhandled error in %s", cls.name)
            console.print(f"[bold red][!] Unhandled error: {exc}[/bold red]")
            if __name__ == "__main__":
                sys.exit(1)
            return None
