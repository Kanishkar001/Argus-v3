"""
argus.cli.commands.web
~~~~~~~~~~~~~~~~~~~~~~~
`web` command — starts the Argus web dashboard in a background thread
and opens it in the default browser.

Usage:
    argus> web
    argus> web --port 8080
    argus> web --host 0.0.0.0 --port 7331 --no-browser
"""
from __future__ import annotations

import argparse
import threading
import webbrowser
import time

from cmd2 import with_argparser, with_category
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from argus.config.settings import WEB_HOST, WEB_PORT

__mixin_name__ = "WebMixin"

TEAL = "#2EC4B6"
console = Console()


class WebMixin:
    _web_parser = argparse.ArgumentParser(description="Launch Argus web dashboard")
    _web_parser.add_argument("--host",       default=WEB_HOST,  help=f"Bind host (default: {WEB_HOST})")
    _web_parser.add_argument("--port", "-p", default=WEB_PORT,  type=int, help=f"Port (default: {WEB_PORT})")
    _web_parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    _web_parser.add_argument("--debug",      action="store_true", help="Enable Flask debug mode")

    @with_argparser(_web_parser)
    @with_category("Utility")
    def do_web(self, args) -> None:
        try:
            from argus.web.app import app
        except ImportError:
            self.perror("Flask is required for the web dashboard. Install it: pip install flask")
            return

        host = args.host
        port = args.port
        url  = f"http://{host}:{port}"

        console.print()
        console.print(Panel(
            Text(f" Argus Web Dashboard → {url} ", justify="center", style=f"bold white on {TEAL}"),
            expand=False, padding=(0, 2), style=TEAL,
        ))
        console.print("[dim]Dashboard running in background. The CLI stays active.[/dim]")
        console.print("[dim]Press Ctrl+C or type 'exit' to stop everything.[/dim]\n")

        def _serve():
            import logging
            log = logging.getLogger("werkzeug")
            log.setLevel(logging.ERROR)
            app.run(host=host, port=port, debug=args.debug, threaded=True, use_reloader=False)

        t = threading.Thread(target=_serve, daemon=True, name="argus-web")
        t.start()

        # Give Flask a moment to bind
        time.sleep(0.8)

        if not args.no_browser:
            webbrowser.open(url)
            console.print(f"[green]✓  Opened {url} in browser[/green]\n")
        else:
            console.print(f"[green]✓  Dashboard available at {url}[/green]\n")

        self._print_status_bar()
