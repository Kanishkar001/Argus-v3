"""
argus.utils.html_report
~~~~~~~~~~~~~~~~~~~~~~~~
Generates a self-contained, dark-themed HTML report from scan output.
No external dependencies — all CSS/JS is inline.
"""
from __future__ import annotations

import datetime
import html
import json
import os
import re
from typing import Any

from argus.config.settings import VERSION, RESULTS_DIR
from argus.utils.util import clean_domain_input


# ── Severity coloring ─────────────────────────────────────────────────────────
def _line_severity(line: str) -> str:
    t = line.lower()
    if re.search(r"critical|exploit|takeover|compromise|severe", t):
        return "alert"
    if re.search(r"\bwarn|risk|exposed|vulnerable|expired|high\b", t):
        return "warn"
    if re.search(r"\[green\]|\[\+\]|✓|secure|valid|\bok\b", t) or "[*]" in line:
        return "ok"
    if re.search(r"^\s*(=+|-+|─+|━+)\s*$", line):
        return "sep"
    return "info"


def _colorize_lines(text: str) -> str:
    """Convert plain text output to styled HTML spans."""
    out = []
    for line in text.splitlines():
        clean = html.escape(
            re.sub(r"\[/?[\w\s#,]*?\]", "", line)   # strip rich markup
        )
        sev = _line_severity(line)
        out.append(f'<div class="line {sev}">{clean}</div>')
    return "\n".join(out)


# ── Severity stats ────────────────────────────────────────────────────────────
def _count_severity(outputs: dict[str, str]) -> dict[str, int]:
    counts = {"alert": 0, "warn": 0, "ok": 0}
    for text in outputs.values():
        for line in text.splitlines():
            t = line.lower()
            if re.search(r"critical|exploit|takeover|compromise|severe", t):
                counts["alert"] += 1
            elif re.search(r"\bwarn|risk|exposed|vulnerable|expired|high\b", t):
                counts["warn"] += 1
    return counts


# ── Main generator ────────────────────────────────────────────────────────────
def generate_html_report(
    data: dict[str, str],
    domain: str,
    modules_used: list[str],
    output_dir: str | None = None,
) -> str:
    """
    Generate a self-contained HTML report.
    Returns the path to the written file.
    """
    domain   = clean_domain_input(domain)
    ts       = datetime.datetime.now()
    ts_str   = ts.strftime("%Y-%m-%d %H:%M:%S")
    ts_file  = ts.strftime("%Y%m%d_%H%M%S")
    sev      = _count_severity(data)

    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), RESULTS_DIR, domain)
    os.makedirs(output_dir, exist_ok=True)

    filename = os.path.join(output_dir, f"{domain}_report_{ts_file}.html")

    # Build module sections HTML
    sections_html = ""
    for mod_name, text in data.items():
        lines_html = _colorize_lines(text)
        esc_name   = html.escape(mod_name)
        sections_html += f"""
        <section class="module-section" id="mod-{html.escape(mod_name.replace(' ','_'))}">
          <div class="mod-header" onclick="toggleSection(this)">
            <span class="mod-title">{esc_name}</span>
            <span class="mod-toggle">▾</span>
          </div>
          <div class="mod-body">
            <div class="output-block">{lines_html}</div>
          </div>
        </section>"""

    # Build nav items
    nav_items = "".join(
        f'<a href="#mod-{html.escape(m.replace(" ","_"))}" class="nav-item">{html.escape(m)}</a>'
        for m in data.keys()
    )

    alert_badge = (
        f'<span class="badge badge-alert">{sev["alert"]} alert(s)</span>' if sev["alert"] else ""
    )
    warn_badge = (
        f'<span class="badge badge-warn">{sev["warn"]} warning(s)</span>' if sev["warn"] else ""
    )
    ok_badge = (
        f'<span class="badge badge-ok">No critical findings</span>'
        if not sev["alert"] and not sev["warn"] else ""
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Argus Report — {html.escape(domain)}</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
  --teal:#2ec4b6;--text:#c9d1d9;--dim:#8b949e;
  --red:#f85149;--yellow:#d29922;--green:#3fb950;--font:'Segoe UI',system-ui,sans-serif;
  --mono:'Cascadia Code','Fira Code',monospace}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;display:flex}}
/* Sidebar */
nav{{width:240px;min-width:240px;background:var(--bg2);border-right:1px solid var(--border);
  height:100vh;overflow-y:auto;position:sticky;top:0;padding:16px 0}}
.nav-logo{{padding:0 16px 16px;border-bottom:1px solid var(--border);margin-bottom:8px}}
.nav-logo h2{{color:var(--teal);font-size:16px}}
.nav-logo small{{color:var(--dim);font-size:11px}}
.nav-item{{display:block;padding:6px 16px;color:var(--dim);text-decoration:none;font-size:12px;
  border-left:2px solid transparent;transition:.15s}}
.nav-item:hover{{color:var(--text);border-color:var(--teal)}}
/* Main */
main{{flex:1;overflow-y:auto;padding:24px;max-width:1100px}}
header{{margin-bottom:24px}}
header h1{{font-size:22px;color:var(--text);margin-bottom:6px}}
.meta{{color:var(--dim);font-size:12px;margin-bottom:12px}}
.badges{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}}
.badge{{padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}}
.badge-alert{{background:#3d1a1a;color:var(--red)}}
.badge-warn{{background:#3a2c00;color:var(--yellow)}}
.badge-ok{{background:#1a3d2b;color:var(--green)}}
/* Summary bar */
.summary-bar{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:28px}}
.stat-card{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px}}
.stat-card .val{{font-size:24px;font-weight:600;color:var(--teal)}}
.stat-card .lbl{{font-size:11px;color:var(--dim);margin-top:2px}}
/* Module sections */
.module-section{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  margin-bottom:12px;overflow:hidden}}
.mod-header{{display:flex;justify-content:space-between;align-items:center;
  padding:12px 16px;cursor:pointer;user-select:none;transition:.15s}}
.mod-header:hover{{background:var(--bg3)}}
.mod-title{{font-weight:500;font-size:14px}}
.mod-toggle{{color:var(--dim);font-size:12px;transition:transform .2s}}
.mod-header.collapsed .mod-toggle{{transform:rotate(-90deg)}}
.mod-body{{border-top:1px solid var(--border)}}
.mod-body.hidden{{display:none}}
.output-block{{padding:12px 16px;overflow-x:auto}}
/* Output lines */
.line{{font-family:var(--mono);font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all}}
.line.alert{{color:var(--red)}}
.line.warn{{color:var(--yellow)}}
.line.ok{{color:var(--green)}}
.line.sep{{color:var(--border)}}
.line.info{{color:var(--text)}}
/* Scrollbar */
::-webkit-scrollbar{{width:5px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
</style>
</head>
<body>
<nav>
  <div class="nav-logo">
    <h2>⬛ ARGUS</h2>
    <small>v{html.escape(VERSION)} Recon Report</small>
  </div>
  {nav_items}
</nav>
<main>
  <header>
    <h1>Recon Report — {html.escape(domain)}</h1>
    <div class="meta">Generated {ts_str} · Argus v{html.escape(VERSION)}</div>
    <div class="badges">{alert_badge}{warn_badge}{ok_badge}</div>
  </header>

  <div class="summary-bar">
    <div class="stat-card"><div class="val">{len(data)}</div><div class="lbl">Modules run</div></div>
    <div class="stat-card"><div class="val" style="color:{'var(--red)' if sev['alert'] else 'var(--green)'}">{sev['alert']}</div><div class="lbl">Critical alerts</div></div>
    <div class="stat-card"><div class="val" style="color:{'var(--yellow)' if sev['warn'] else 'var(--green)'}">{sev['warn']}</div><div class="lbl">Warnings</div></div>
    <div class="stat-card"><div class="val">{sum(len(t.splitlines()) for t in data.values())}</div><div class="lbl">Output lines</div></div>
  </div>

  {sections_html}
</main>
<script>
function toggleSection(header){{
  header.classList.toggle('collapsed');
  const body=header.nextElementSibling;
  body.classList.toggle('hidden');
}}
// Auto-expand first section
document.querySelectorAll('.mod-header')[0]?.click();
document.querySelectorAll('.mod-header')[0]?.click();
</script>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)

    return filename
