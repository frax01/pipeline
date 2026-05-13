"""Extract top 10 (or all if fewer) findings per category for manual verification.
NOT a classifier — just data extraction for human review.
Outputs: top10_to_verify.json with normalized schema."""

import json
import re
from pathlib import Path

BASE = Path(r"C:/Users/francesco/Desktop/pipeline/analysisAllData")

# (cat_id, cat_name, vp_json_path, schema_type, max_n)
CATEGORIES = [
    (1,  "sql-injection",            BASE / "0_tool_mcp_guard/sql-injection-static/filtered/llm_analysis/vp.json",            "guard_static", 10),
    (2,  "dangerous-capabilities",   BASE / "0_tool_mcp_security_scan/dangerous-capabilities/filtered/llm_analysis/vp.json",   "secscan_tool", 10),
    (3,  "credential-leak",          BASE / "0_tool_mcp_watch/credential-leak/filtered/llm_analysis/vp.json",                  "watch",        10),
    (4,  "ssrf",                     BASE / "0_tool_mcp_guard/ssrf-static/filtered/llm_analysis/vp.json",                      "guard_static", 10),
    (5,  "untrusted-content",        BASE / "0_tool_mcp_scan/server-level/filtered/llm_analysis/vp.json",                      "scan_server",  10),
    (6,  "path-traversal-static",    BASE / "0_tool_mcp_guard/path-traversal-static/filtered/llm_analysis/vp.json",            "guard_static", 10),
    (7,  "command-injection-static", BASE / "0_tool_mcp_guard/command-injection-static/filtered/llm_analysis/vp.json",         "guard_static", 10),
    (8,  "code-injection-static",    BASE / "0_tool_mcp_guard/code-injection-static/filtered/llm_analysis/vp.json",            "guard_static", 10),
    (9,  "input-validation",         BASE / "0_tool_mcp_watch/input-validation/filtered/llm_analysis/vp.json",                 "watch",        10),
    (10, "protocol-violation",       BASE / "0_tool_mcp_watch/protocol-violation/filtered/llm_analysis/vp.json",               "watch",        10),
    (11, "prompt-injection-E001",    BASE / "0_tool_mcp_scan/tool-level/filtered/llm_analysis/vp.json",                        "scan_tool",    10),
    (12, "insecure-deserialization", BASE / "0_tool_mcp_guard/insecure-deserialization-static/filtered/llm_analysis/vp.json",  "guard_static", 10),
    (13, "sensitive-file-access",    BASE / "0_tool_mcp_shield/sensitive-file-access/llm_analysis/vp.json",                    "shield",       11),  # all 11
    (14, "sensitive-info-disclosure",None,                                                                                      "multi_info",    9),
    (15, "access-control",           BASE / "0_tool_mcp_watch/access-control/filtered/llm_analysis/vp.json",                   "watch",         7),
    (16, "data-exfiltration",        BASE / "0_tool_mcp_watch/data-exfiltration/filtered/llm_analysis/vp.json",                "watch",         2),
    (17, "tool-shadowing",           BASE / "0_tool_mcp_shield/shadowing-detected/llm_analysis/vp.json",                       "shield",        1),
]

# Extract line number from mcp-guard description text
_LINE_RE = re.compile(r"at line (\d+)\. Code: (.+?)$", re.DOTALL)

def extract_guard_static(f):
    desc = f.get("description", "")
    m = _LINE_RE.search(desc)
    line = int(m.group(1)) if m else None
    snippet = m.group(2).strip() if m else desc[:300]
    return {
        "server_url": f.get("server_url"),
        "server_name": f.get("server_name"),
        "file": f.get("file"),
        "line": line,
        "snippet": snippet,
        "hc_reason": f.get("_hc_reason"),
        "language": f.get("language"),
    }

def extract_watch(f):
    return {
        "server_url": f.get("github_url"),
        "server_name": f.get("server_name"),
        "file": f.get("file"),
        "line": f.get("line"),
        "snippet": f.get("evidence", ""),
        "id": f.get("id"),
        "category": f.get("category"),
        "filter_confidence": f.get("filter_confidence"),
        "language": f.get("language"),
    }

def extract_shield(f):
    return {
        "server_url": f.get("server_url"),
        "server_name": f.get("server_name"),
        "tool_name": f.get("tool_name"),
        "tool_description": f.get("tool_description", "")[:1500],
        "descriptions_trigger": f.get("descriptions"),
        "llm_analysis": (f.get("llm_analysis") or "")[:600],
        "file": None, "line": None, "snippet": None,
    }

def extract_secscan_tool(f):
    details = f.get("details", "")
    try:
        tools = json.loads(details) if isinstance(details, str) else details
        tool_names = [t.get("name", "?") for t in tools[:5]] if isinstance(tools, list) else []
    except Exception:
        tool_names = []
        tools = []
    return {
        "server_url": f.get("server_url"),
        "server_name": f.get("server_name"),
        "title": f.get("title"),
        "tool_names": tool_names,
        "tools_full": tools if isinstance(tools, list) else [],
        "hc_reason": f.get("_hc_reason"),
        "file": None, "line": None, "snippet": None,
    }

def extract_scan_server(f):
    extra = f.get("extra_data", {})
    return {
        "server_url": f.get("server_url"),
        "reason": extra.get("reason", ""),
        "example": extra.get("example", ""),
        "risk_score": extra.get("risk_score"),
        "file": None, "line": None, "snippet": None,
    }

def extract_scan_tool(f):
    extra = f.get("extra_data", {})
    return {
        "server_url": f.get("server_url"),
        "tool_name": f.get("tool_name"),
        "description": (extra.get("description") or "")[:800],
        "evidence": extra.get("evidence", ""),
        "thought_process": (extra.get("thought_process") or "")[:600],
        "risk_score": extra.get("risk_score"),
        "file": None, "line": None, "snippet": None,
    }

EXTRACTORS = {
    "guard_static": extract_guard_static,
    "watch": extract_watch,
    "shield": extract_shield,
    "secscan_tool": extract_secscan_tool,
    "scan_server": extract_scan_server,
    "scan_tool": extract_scan_tool,
}

def load_vp(path):
    d = json.load(open(path, encoding="utf-8"))
    return d.get("findings", []) if isinstance(d, dict) else d

def collect_sensitive_info():
    """Cat 14: multi-source — merge top 9 from 3 sources by rank."""
    sources = [
        BASE / "0_tool_mcp_guard/sensitive-info-disclosed-fuzzing/filtered/llm_analysis/vp.json",
        BASE / "0_tool_mcp_guard/information-disclosure-fuzzing/filtered/llm_analysis/vp.json",
        BASE / "0_tool_mcp_guard/protocol-information-disclosure/filtered/llm_analysis/vp.json",
    ]
    out = []
    for s in sources:
        if not s.exists():
            continue
        for f in load_vp(s):
            out.append({
                "server_url": f.get("server_url"),
                "server_name": f.get("server_name"),
                "file": f.get("file"),
                "line": None,
                "snippet": (f.get("description") or f.get("evidence") or "")[:600],
                "payload": (f.get("payload") or "")[:400],
                "response": (f.get("response") or "")[:600],
                "_source": s.parent.parent.parent.name,
            })
    return out[:9]

def main():
    out = {"categories": []}
    for cat_id, name, path, schema, max_n in CATEGORIES:
        if schema == "multi_info":
            findings = collect_sensitive_info()
        else:
            extractor = EXTRACTORS[schema]
            raw = load_vp(path)
            findings = [extractor(f) for f in raw[:max_n]]
        out["categories"].append({
            "id": cat_id,
            "name": name,
            "schema": schema,
            "count": len(findings),
            "findings": findings,
        })
        print(f"[{cat_id:2d}] {name:30s} -> {len(findings)} findings")

    out_path = Path(r"C:/Users/francesco/Desktop/pipeline/top10_to_verify.json")
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nWritten: {out_path}")
    print(f"Total findings to verify: {sum(c['count'] for c in out['categories'])}")

if __name__ == "__main__":
    main()
