from ..core.catalog_cache import (
    tools,
    tools_mapping,
    TOOL_TAGS,
    SECTION_TOOL_NUMBERS,
)

VERSION = "2.0"
AUTHOR = "Jason13"
TEAL = "#2EC4B6"
CATALOG_FILENAME = "modules.json"
ARGUS_CATALOG_ENV = "ARGUS_CATALOG_PATH"

SECTION_NAMES = {
    "network_infrastructure": "Network & Infrastructure",
    "web_application_analysis": "Web Application Analysis",
    "security_threat_intelligence": "Security & Threat Intelligence",
}

NUMERIC_OPTION_HINTS = {
    "max_pages",
    "count",
    "warn_ms",
    "resume_count",
    "size",
    "timeout",
    "history_days",
    "depth",
    "limit",
    "short_window",
    "long_window",
    "threads",
    "port",
    "ports",
    "retries",
}

ALL_KNOWN_MODULE_OPTIONS = {
    o.replace("-", "_").lower()
    for t in tools
    for o in (t.get("options_meta") or [])
}
