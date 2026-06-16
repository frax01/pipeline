"""Analisi esplorativa protocol-violation."""
import json, re
from collections import Counter
from pathlib import Path

SRC = Path(__file__).parent / "protocol_violation_filtered.json"
with open(SRC, encoding="utf-8") as f:
    d = json.load(f)
findings = d["findings"]

insecure = [x for x in findings if x["id"] == "INSECURE_TRANSPORT"]
session  = [x for x in findings if x["id"] == "SESSION_ID_IN_URL"]

print(f"INSECURE_TRANSPORT: {len(insecure)}  |  SESSION_ID_IN_URL: {len(session)}")
print()

# ── Categorize INSECURE_TRANSPORT ────────────────────────────────────────────
LOC_PAT     = re.compile(r"localhost|127\.0\.0\.1|0\.0\.0\.0|::1", re.I)
PRIV_PAT    = re.compile(r"192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.", re.I)
EXAMPLE_PAT = re.compile(r"e\.g\.|your-domain|your-public-ip|your-server|example\.com|placeholder|<host>|<url>|\[host\]|\[url\]", re.I)
COMMENT_PAT = re.compile(r"^\s*[#/*]|^\s*\*\s|^\s*//", re.I)
DOCSTR_PAT  = re.compile(r'""".*http://|#.*http://|//.*http://', re.I)
ENV_PAT     = re.compile(r"os\.getenv|process\.env|getenv\(", re.I)
TEST_PAT    = re.compile(r"test|spec|mock|fixture|\.test\.|\.spec\.", re.I)
VALIDATOR_PAT = re.compile(r"must include|must start|URL scheme must|cannot start with http|ValidationError.*url|raise.*url", re.I)
DOCS_ONLY_PAT = re.compile(r"http://www\.|http://github\.com|http://iiif\.io|http://gtkwave|DTD PLIST|iiif\.io/api", re.I)

cats = {"localhost": [], "private_ip": [], "example/placeholder": [],
        "comment": [], "env_var_default": [], "validator_doc": [],
        "external_doc_url": [], "test_code": [], "other": []}

for x in insecure:
    ev = x.get("evidence") or ""
    fp = x.get("file") or ""
    if LOC_PAT.search(ev):
        cats["localhost"].append(x)
    elif PRIV_PAT.search(ev):
        cats["private_ip"].append(x)
    elif VALIDATOR_PAT.search(ev):
        cats["validator_doc"].append(x)
    elif EXAMPLE_PAT.search(ev):
        cats["example/placeholder"].append(x)
    elif COMMENT_PAT.match(ev) or DOCSTR_PAT.search(ev):
        cats["comment"].append(x)
    elif DOCS_ONLY_PAT.search(ev):
        cats["external_doc_url"].append(x)
    elif TEST_PAT.search(fp) or TEST_PAT.search(ev):
        cats["test_code"].append(x)
    elif ENV_PAT.search(ev):
        cats["env_var_default"].append(x)
    else:
        cats["other"].append(x)

print("=== INSECURE_TRANSPORT categories ===")
for cat, items in cats.items():
    print(f"  {len(items):4d}  {cat}")
print()

# Show samples of each non-trivial category
for cat in ["env_var_default", "external_doc_url", "other"]:
    items = cats[cat]
    print(f"--- {cat} ({len(items)}) ---")
    for x in items[:15]:
        ev = (x.get("evidence") or "")[:120]
        print(f"  [{x['server_name'][:35]}] {x['file'][-45:]}")
        print(f"    {repr(ev)}")
    print()

# ── SESSION_ID_IN_URL ─────────────────────────────────────────────────────────
print("=== SESSION_ID_IN_URL samples ===")
for x in session[:20]:
    ev = (x.get("evidence") or "")[:120]
    print(f"  [{x['server_name'][:35]}] {x['file'][-45:]}  conf={x.get('filter_confidence','')}")
    print(f"    {repr(ev)}")
    print()
