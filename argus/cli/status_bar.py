from rich.console import Console

console = Console()

def print_status_bar(cli) -> None:
    tgt = cli.target or "None"
    mod = f"{cli.selected_module['name']} ({cli.selected_module['number']})" if cli.selected_module else "None"
    th = str(cli.threads)
    qm = "on" if cli.quiet_mode else "off"
    console.print(f"[dim][target:{tgt}] [module:{mod}] [threads:{th}] [quiet:{qm}][/dim]")
