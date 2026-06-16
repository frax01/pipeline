"""Analisi esplorativa dei finding steganographic-attack."""
import json, re
from pathlib import Path
from collections import Counter

SRC = Path(__file__).parent / "steganographic_attack_filtered.json"

with open(SRC, encoding="utf-8") as f:
    d = json.load(f)
findings = d["findings"]

ansi = [x for x in findings if x["id"] == "ANSI_ESCAPE_INJECTION"]
ws   = [x for x in findings if x["id"] == "WHITESPACE_INJECTION"]

print(f"Total: {len(findings)}  |  ANSI: {len(ansi)}  |  WS: {len(ws)}")
print()

# ── ANSI ─────────────────────────────────────────────────────────────────────
cli_write_pat  = re.compile(r"process\.std(?:out|err)\.write|this\.stream\.write|getPreferredOutputStream|writeEmitter\.fire|print\(.*\\x1b", re.I)
hidden_prop_pat= re.compile(r"^\s*(HIDDEN|hidden)\s*:", re.I)
comment_pat    = re.compile(r"^\s*[#/*]|Strip CSI|Strip.*escape", re.I)
dts_pat        = re.compile(r"\.d\.ts$")

cats = {"cli_terminal_ui": [], "hidden_property": [], "comment": [], "dts": [], "other": []}
for x in ansi:
    ev = x.get("evidence", "")
    fp = x.get("file", "")
    if dts_pat.search(fp):
        cats["dts"].append(x)
    elif comment_pat.match(ev):
        cats["comment"].append(x)
    elif hidden_prop_pat.match(ev):
        cats["hidden_property"].append(x)
    elif cli_write_pat.search(ev):
        cats["cli_terminal_ui"].append(x)
    else:
        cats["other"].append(x)

print("=== ANSI categories ===")
for cat, items in cats.items():
    print(f"  {cat}: {len(items)}")
    for x in items[:3]:
        print(f"    [{x['server_name'][:35]}] {x['file'][-45:]}")
        print(f"      {repr(x.get('evidence','')[:100])}")
    print()

# ── WHITESPACE ────────────────────────────────────────────────────────────────
print("=== WHITESPACE_INJECTION samples ===")
ws_tool = [x for x in ws if x.get("filter_confidence") == "whitespace_in_tool_definition"]
ws_ext  = [x for x in ws if x.get("filter_confidence","").startswith("extreme_whitespace")]

print(f"  whitespace_in_tool_definition: {len(ws_tool)}")
for x in ws_tool[:8]:
    ev = x.get("evidence","")
    print(f"    [{x['server_name'][:35]}] {x['file'][-40:]}")
    print(f"      {repr(ev[:120])}")
print()
print(f"  extreme_whitespace: {len(ws_ext)}")
# Check if it's indentation or actual content injection
for x in ws_ext[:10]:
    ev = x.get("evidence","")
    print(f"    [{x['server_name'][:35]}] {x['file'][-40:]} conf={x['filter_confidence']}")
    print(f"      {repr(ev[:120])}")
print()

# exa-mcp-server extreme whitespace — is it a minified file?
exa = [x for x in ws_ext if "exa" in x.get("server_name","")]
print(f"  exa-mcp-server extreme ws findings: {len(exa)}")
for x in exa:
    print(f"    {x['file']}: conf={x['filter_confidence']}")
