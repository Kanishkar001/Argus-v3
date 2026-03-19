from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import SIMPLE_HEAVY

from argus.cli.logo import TEAL

console = Console()


def _header(title: str) -> Panel:
    return Panel(
        Text(f" {title} ", justify="center", style=f"bold white on {TEAL}"),
        expand=False,
        padding=(0, 2),
        style=TEAL,
    )


def ack_change_panel(title: str, pairs) -> None:
    console.print()
    console.print(_header(title))
    console.print()
    tbl = Table(box=SIMPLE_HEAVY)
    tbl.add_column("Field", style="cyan", no_wrap=True)
    tbl.add_column("Value", style="green")
    for k, v in pairs:
        tbl.add_row(str(k), str(v))
    console.print(tbl)
    console.print()


def recommendations_panel(lines) -> None:
    if not lines:
        return
    body = "\n".join(f"• {ln}" for ln in lines)
    console.print()
    console.print(
        Panel(
            body,
            title=Text(" Recommended Next Steps ", style=f"bold white on {TEAL}"),
            border_style=TEAL,
            padding=(1, 2),
        )
    )
    console.print()
