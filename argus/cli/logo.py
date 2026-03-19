from rich.console import Console
from rich.panel import Panel

TEAL = "#2EC4B6"

console = Console()

def logo(version: str, modules: int, author: str) -> None:
    art = """
     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
    ███████║██████╔╝██║  ███╗██║   ██║███████╗
    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
    """.strip(
        "\n"
    )
    colored = "\n".join(f"[bold {TEAL}]{line}[/bold {TEAL}]" for line in art.splitlines())
    desc = f"""
[bold {TEAL}]The Ultimate Information Gathering Tool[/bold {TEAL}]

Version: [bold green]{version}[/bold green]    Modules: [bold yellow]{modules}[/bold yellow]    Coded by: [bold magenta]{author}[/bold magenta]
""".strip()
    console.print(Panel(f"{colored}\n{desc}", border_style=TEAL, padding=(1, 4)), justify="center")
    console.print(f"[bold {TEAL}]Type 'help' to see available commands.[/bold {TEAL}]")
