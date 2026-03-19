from dataclasses import dataclass, field
from typing import List, Dict, Set

SECTION_NAMES = {
    "network_infrastructure": "Network & Infrastructure",
    "web_application_analysis": "Web Application Analysis",
    "security_threat_intelligence": "Security & Threat Intelligence",
    "run_all": "Run All Scripts",
    "special": "Special Mode",
}

@dataclass
class Tool:
    number: str
    name: str
    script: str
    section: str
    description: str = ""
    primary_input: str = ""
    options_meta: List[str] = field(default_factory=list)
    options_help: Dict[str, str] = field(default_factory=dict)

def normalize_catalog_ids(cat: Dict) -> Dict:
    seen = set()
    for key, mods in cat.items():
        if not isinstance(mods, list):
            continue
        for m in mods:
            mid = str(m.get("id", "")).strip()
            if not mid or mid in seen:
                mid = str(max([int(x) for x in seen] + [0]) + 1)
                m["id"] = int(mid)
            seen.add(mid)
    return cat

def catalog_to_tools(obj: Dict) -> List[Tool]:
    out, id_seen = [], set()
    for cat_key, section_name in SECTION_NAMES.items():
        for m in obj.get(cat_key, []):
            mid = str(m.get("id", "")).strip()
            if not mid or mid in id_seen:
                mid = str(max([int(x) for x in id_seen] + [0]) + 1)
            id_seen.add(mid)
            out.append(
                Tool(
                    number=mid,
                    name=m.get("name", f"Module{mid}"),
                    script=m.get("script", ""),
                    section=section_name,
                    description=m.get("description", ""),
                    primary_input=m.get("primary_input", ""),
                    options_meta=m.get("options", []),
                    options_help=m.get("options_help", {}),
                )
            )
    return out

def compute_tags(tool: Tool) -> Set[str]:
    t, n, d, s = set(), tool.name.lower(), tool.description.lower(), tool.section.lower()
    if "dns" in n or "dns" in d:
        t.add("dns")
    if "tls" in n or "ssl" in n or "certificate" in n or "cert" in d:
        t.add("tls")
    if any(x in n or x in d for x in ["email", "spf", "dmarc", "dkim", "mail"]):
        t.add("email")
    if "cloud" in n or "s3" in d or "bucket" in d:
        t.add("cloud")
    if "web" in s or tool.section == "Web Application Analysis":
        t.add("web")
    if any(x in n for x in ["recon", "enum"]) or "enumeration" in d:
        t.add("recon")
    if "scan" in n or "scanner" in n:
        t.add("fast")
    if any(x in n for x in ["deep", "changelog", "inventory", "history"]):
        t.add("heavy")
    return t
