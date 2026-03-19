"""
argus.web.app
~~~~~~~~~~~~~~
Flask-based web dashboard for Argus.
Provides a browser UI to browse modules, run scans with real-time SSE
output, view scan history, and manage API keys.

Launch via:  argus> web
         or: python -m argus.web
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Generator

from flask import (
    Flask, Response, jsonify, render_template,
    request, stream_with_context,
)

# ── Argus internals ───────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from argus.core.catalog_cache import tools, SECTION_TOOL_NUMBERS
from argus.config.settings import (
    API_KEYS, RESULTS_DIR, WEB_HOST, WEB_PORT, WEB_DEBUG, VERSION,
)
from argus.utils.util import clean_domain_input

# ── Flask app ─────────────────────────────────────────────────────────────────
TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR   = Path(__file__).parent / "static"

app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR),
)
app.secret_key = os.urandom(24)

# ── In-memory scan registry ───────────────────────────────────────────────────
_scans: dict[str, dict] = {}          # scan_id → scan record
_output_queues: dict[str, queue.Queue] = {}   # scan_id → SSE queue


def _new_scan_id() -> str:
    return f"scan_{int(time.time() * 1000)}"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", version=VERSION)


@app.route("/api/modules")
def api_modules():
    section = request.args.get("section", "").lower()
    search  = request.args.get("q", "").lower()

    filtered = [
        {
            "number":      t["number"],
            "name":        t["name"],
            "section":     t["section"],
            "description": t.get("description", ""),
            "script":      t.get("script", ""),
        }
        for t in tools
        if t.get("script")
        and t["section"] not in ("Run All Scripts", "Special Mode")
        and (not section or section in t["section"].lower())
        and (not search or search in t["name"].lower() or search in t.get("description", "").lower())
    ]
    return jsonify({"modules": filtered, "total": len(filtered)})


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    data    = request.get_json(force=True)
    target  = data.get("target", "").strip()
    mod_ids = data.get("modules", [])
    threads = int(data.get("threads", 4))

    if not target:
        return jsonify({"error": "No target specified"}), 400
    if not mod_ids:
        return jsonify({"error": "No modules selected"}), 400

    domain  = clean_domain_input(target)
    scan_id = _new_scan_id()

    _scans[scan_id] = {
        "id":        scan_id,
        "target":    domain,
        "modules":   mod_ids,
        "threads":   threads,
        "status":    "running",
        "started":   datetime.now().isoformat(),
        "finished":  None,
        "outputs":   {},
        "errors":    [],
    }
    _output_queues[scan_id] = queue.Queue()

    def _worker():
        q = _output_queues[scan_id]
        scan = _scans[scan_id]

        # Map mod ids → tool records
        tool_map = {t["number"]: t for t in tools}

        for mid in mod_ids:
            tool = tool_map.get(str(mid))
            if not tool or not tool.get("script"):
                q.put({"type": "error", "module": mid, "text": f"Module {mid} not found."})
                continue

            mod_name   = tool["name"]
            script_mod = os.path.splitext(tool["script"])[0]
            cmd = [sys.executable, "-m", f"argus.modules.{script_mod}", domain, str(threads)]

            q.put({"type": "start", "module": mod_name})
            buf = []
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, env={**os.environ}
                )
                for line in iter(proc.stdout.readline, ""):
                    line = line.rstrip("\n")
                    if line:
                        buf.append(line)
                        q.put({"type": "output", "module": mod_name, "text": line})
                proc.wait()
            except Exception as exc:
                err = str(exc)
                scan["errors"].append({"module": mod_name, "error": err})
                q.put({"type": "error", "module": mod_name, "text": err})
                continue

            output_text = "\n".join(buf)
            scan["outputs"][mod_name] = output_text
            q.put({"type": "done", "module": mod_name, "lines": len(buf)})

        scan["status"]   = "finished"
        scan["finished"] = datetime.now().isoformat()
        q.put({"type": "scan_done", "scan_id": scan_id})

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/stream")
def api_scan_stream(scan_id: str):
    if scan_id not in _output_queues:
        return jsonify({"error": "Unknown scan"}), 404

    def _generate() -> Generator[str, None, None]:
        q = _output_queues[scan_id]
        while True:
            try:
                msg = q.get(timeout=30)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("type") == "scan_done":
                    break
            except queue.Empty:
                yield "data: {\"type\":\"ping\"}\n\n"

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/scan/<scan_id>")
def api_scan_status(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    return jsonify(scan)


@app.route("/api/scans")
def api_scan_list():
    return jsonify({
        "scans": [
            {k: v for k, v in s.items() if k != "outputs"}
            for s in reversed(list(_scans.values()))
        ]
    })


@app.route("/api/api_status")
def api_api_status():
    return jsonify({
        k: bool(v) for k, v in API_KEYS.items()
    })


@app.route("/api/results/<scan_id>")
def api_results(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "target":  scan["target"],
        "outputs": scan["outputs"],
        "errors":  scan["errors"],
    })


# ── Entry point ───────────────────────────────────────────────────────────────

def run_server(host: str = WEB_HOST, port: int = WEB_PORT, debug: bool = WEB_DEBUG):
    print(f"\n  Argus Web Dashboard v{VERSION}")
    print(f"  Running on  http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)


if __name__ == "__main__":
    run_server()
