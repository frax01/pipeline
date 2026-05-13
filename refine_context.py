"""For findings where the cached file content drifted from the original line,
search for the original snippet text in the cached file and produce a corrected context."""
import json
import re
from pathlib import Path

ROOT = Path(r"C:/Users/francesco/Desktop/pipeline")
CACHE = ROOT / "top10_cache"

def cache_key(owner, repo, path):
    safe = path.replace("/", "__").replace("\\", "__")
    return CACHE / f"{owner}__{repo}__{safe}"

def parse_repo(url):
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", url or "")
    if not m: return None, None
    return m.group(1), m.group(2).rstrip(".git")

def extract_search_key(snippet):
    """Get the most specific substring to search for."""
    s = (snippet or "").strip()
    # Remove leading "Code: " if present
    s = re.sub(r"^Code:\s*", "", s)
    # Strip surrounding noise
    s = s.strip("\"' ")
    # Take a recognizable middle portion (executable code line)
    # Drop common boilerplate
    if len(s) > 120:
        s = s[:120]
    return s

src = json.load(open(ROOT / "audit_context.json", encoding="utf-8"))

for cat in src["categories"]:
    for f in cat["findings"]:
        if not f.get("file") or not f.get("server_url"):
            continue
        owner, repo = parse_repo(f["server_url"])
        if not owner:
            continue
        ck = cache_key(owner, repo, f["file"])
        if not ck.exists():
            continue
        content = ck.read_text(encoding="utf-8", errors="replace")
        if content == "__NOT_FOUND__":
            continue
        lines = content.split("\n")
        # If existing context line matches snippet, no need to refine
        snippet = f.get("snippet", "")
        if not snippet:
            continue
        search_key = extract_search_key(snippet)
        # Try to find search_key substring in the file
        # Try progressively shorter prefixes
        for trim in [search_key, search_key[:80], search_key[:50], search_key[:30]]:
            if not trim: continue
            for i, ln in enumerate(lines, 1):
                if trim in ln:
                    # Found! Update context
                    ctx = 7
                    lo = max(1, i - ctx)
                    hi = min(len(lines), i + ctx)
                    f["_context_start"] = lo
                    f["_context_lines"] = lines[lo-1:hi]
                    f["_resolved_line"] = i
                    f["_original_line_drifted"] = (f.get("line") != i)
                    f["_permalink"] = f"https://github.com/{owner}/{repo}/blob/HEAD/{f['file']}#L{i}"
                    break
            else:
                continue
            break

(ROOT / "audit_context.json").write_text(json.dumps(src, indent=2, ensure_ascii=False), encoding="utf-8")
print("Refined audit_context.json")

# Stats
resolved = drifted = 0
for cat in src["categories"]:
    for f in cat["findings"]:
        if "_resolved_line" in f:
            resolved += 1
            if f.get("_original_line_drifted"):
                drifted += 1
print(f"Resolved by snippet match: {resolved}, of which drifted: {drifted}")
