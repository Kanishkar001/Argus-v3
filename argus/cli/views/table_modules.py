from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import SIMPLE_HEAVY
from rich.align import Align
from argus.cli.logo import TEAL
from argus.core.catalog_cache import tools, TOOL_TAGS, SECTION_NAMES

console = Console()

SECTIONS = (
    "Network & Infrastructure",
    "Web Application Analysis",
    "Security & Threat Intelligence",
)
SECTION_COLOR = "magenta"


def _header(title: str) -> Panel:
    return Panel(
        Text(f" {title} ", justify="center", style=f"bold white on {TEAL}"),
        expand=False,
        padding=(0, 2),
        style=TEAL,
    )


def _print_centered(renderable, pct: float = 0.90) -> None:
    """
    Render `renderable` at `pct` of terminal width, centered.
    Example: pct=0.90 -> ~5% margins on left and right.
    """
    term_w = console.size.width or 80
    inner_w = max(20, min(term_w, int(term_w * pct)))
    # prefer explicit width & no expand so Align can center it
    try:
        renderable.width = inner_w
        # if the renderable supports expand, disable it
        if hasattr(renderable, "expand"):
            renderable.expand = False
    except Exception:
        pass
    console.print(Align(renderable, align="center", width=term_w))


def display_table(
    section_filter: Optional[str] = None,
    tag_filter: Optional[str] = None,
    short: bool = False,
    show_tags: bool = False,
    details: bool = False,
) -> None:
    if section_filter not in SECTIONS:
        section_filter = None
    if tag_filter:
        tag_filter = tag_filter.lower()

    if short:
        rows = []
        for t in tools:
            if section_filter and t["section"] != section_filter:
                continue
            if tag_filter and tag_filter not in TOOL_TAGS.get(t["number"], set()):
                continue
            tags = "".join(f"[{tg}]" for tg in sorted(TOOL_TAGS.get(t["number"], set()))) if show_tags else ""
            rows.append(f"{t['number']:>4}  {t['name']} {tags}")
        console.print()
        console.print(_header("Modules (Short)"))
        console.print()
        if rows:
            console.print("\n".join(rows))
        else:
            console.print(Text("No matching modules.", style="bold yellow"))
        console.print()
        return

    if details:
        console.print()
        console.print(_header("Modules (Detailed)"))
        for sec_key, sec_name in SECTION_NAMES.items():
            if sec_key in ("run_all", "special"):
                continue
            mods = [
                t
                for t in tools
                if t["section"] == sec_name
                and (not tag_filter or tag_filter in TOOL_TAGS.get(t["number"], set()))
            ]
            if not mods:
                continue
            console.print()
            console.print(Text(sec_name, style="bold underline"))
            table = Table(box=SIMPLE_HEAVY, expand=False)  # width handled by _print_centered
            table.add_column("ID", style="yellow", no_wrap=True)
            table.add_column("Name", style=TEAL, ratio=1, overflow="fold")
            table.add_column("Description", style="white", ratio=2, overflow="fold")
            table.add_column("Input", style="cyan", no_wrap=True)
            for t in mods:
                table.add_row(
                    t["number"],
                    t["name"],
                    t.get("description", "—"),
                    t.get("primary_input", "—"),
                )
            _print_centered(table, 0.95)
        console.print()
        return

    if section_filter:
        console.print()
        console.print(_header(section_filter))
        sty = "cyan" if section_filter == SECTIONS[0] else "green" if section_filter == SECTIONS[1] else "magenta"
        table = Table(box=SIMPLE_HEAVY, expand=False)  # width handled by _print_centered
        table.add_column(section_filter, style=sty, ratio=1, overflow="fold")
        for t in tools:
            if t["section"] != section_filter:
                continue
            if tag_filter and tag_filter not in TOOL_TAGS.get(t["number"], set()):
                continue
            tags = " ".join(f"[{tg}]" for tg in sorted(TOOL_TAGS.get(t["number"], set()))) if show_tags else ""
            table.add_row(f"[bold]{t['number']}[/bold]. {t['name']} {tags}")
        _print_centered(table, 0.95)
        console.print()
        return

    if tag_filter:
        console.print()
        console.print(_header(f"Modules tagged: {tag_filter}"))
        mods = [t for t in tools if tag_filter in TOOL_TAGS.get(t["number"], set())]

        table = Table(box=SIMPLE_HEAVY, expand=False)  # width handled by _print_centered
        table.add_column("ID", style="yellow", no_wrap=True)
        table.add_column("Name", style="green", ratio=2, overflow="fold")
        table.add_column("Section", style=SECTION_COLOR, ratio=1, overflow="fold")
        for t in mods:
            table.add_row(t["number"], t["name"], t["section"])
        _print_centered(table, 0.95)
        console.print()
        return

    console.print()
    console.print(_header("Modules"))
    table = Table(
        box=SIMPLE_HEAVY,
        caption="[bold]Usage:[/bold] use <module-id> / run <module-id> [target]",
        expand=False,  # width handled by _print_centered
        pad_edge=True,
    )
    table.add_column(SECTIONS[0], style="cyan", ratio=1, overflow="fold")
    table.add_column(SECTIONS[1], style="green", ratio=1, overflow="fold")
    table.add_column(SECTIONS[2], style=SECTION_COLOR, ratio=1, overflow="fold")

    by_sec = {s: [] for s in SECTIONS}
    for t in tools:
        if t["section"] in SECTIONS:
            tags = " ".join(f"[{tg}]" for tg in sorted(TOOL_TAGS.get(t["number"], set()))) if show_tags else ""
            by_sec[t["section"]].append(f"[bold]{t['number']}[/bold]. {t['name']} {tags}")

    max_rows = max((len(v) for v in by_sec.values()), default=0)
    for i in range(max_rows):
        row = [by_sec[s][i] if i < len(by_sec[s]) else "—" for s in SECTIONS]
        table.add_row(*row)

    _print_centered(table, 0.95)
    console.print()


def module_info_table(
    tool: dict,
    current_target: Optional[str],
    threads: int,
    curr_opts: dict,
    show_full: bool = False,
) -> Table:
    def color_val(label: str, value: str, changed: bool = False) -> str:
        if changed:
            return f"[green]{value}[/green]"
        if value in {"Not set", "None", "—"}:
            return f"[bright_black]{value}[/bright_black]"
        if label == "Section":
            return f"[{SECTION_COLOR}]{value}[/{SECTION_COLOR}]"
        if label == "Tags" and value != "None":
            return f"[{SECTION_COLOR}]{value}[/{SECTION_COLOR}]"
        return value

    table = Table(
        title=f"Module: {tool['name']} ({tool['number']})",
        box=SIMPLE_HEAVY,
        caption="[bold yellow]⇒ Type 'run' to start[/bold yellow]",
        caption_justify="center",
        expand=False,  # let width be controlled by the printer
        pad_edge=True,
    )
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", ratio=1, overflow="fold")

    table.add_row("Section", color_val("Section", tool["section"]))
    desc = tool.get("description") or "None"
    table.add_row("Description", color_val("Description", desc))
    primary_in = tool.get("primary_input") or "None"
    table.add_row("Target Type", color_val("Primary Input", primary_in))

    tgt_changed = bool(current_target)
    table.add_row("Target", color_val("Target", current_target or "Not set", tgt_changed))

    thr_changed = threads > 1
    table.add_row("Threads", color_val("Threads", str(threads), thr_changed))

    tags = " ".join(sorted(TOOL_TAGS.get(tool["number"], set()))) or "None"
    table.add_row("Tags", color_val("Tags", tags))

    # options
    opts_meta = tool.get("options_meta") or []
    if opts_meta:
        for o in opts_meta:
            norm = o.replace("-", "_").lower()
            val = curr_opts.get(norm, "Not set")
            changed = val != "Not set"
            if show_full:
                tip = tool.get("options_help", {}).get(o, "") or f"Set {o}"
                val_out = (
                    f"{color_val(o, str(val), changed)} ({tip})"
                    if tip else color_val(o, str(val), changed)
                )
            else:
                val_out = color_val(o, str(val), changed)
            table.add_row(f"opt: {o}", val_out)
    else:
        table.add_row("Module Options", "[bright_black]None[/bright_black]")

    return table
