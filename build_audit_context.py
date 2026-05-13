"""For each top-10 finding, extract source context (±7 lines around target line).
Output: audit_context.json — ready-to-read by human."""

import json
from pathlib import Path

ROOT = Path(r"C:/Users/francesco/Desktop/pipeline")
CACHE = ROOT / "top10_cache"

def cache_key(owner, repo, path):
    safe = path.replace("/", "__").replace("\\", "__")
    return CACHE / f"{owner}__{repo}__{safe}"

def parse_repo(url):
    import re
    if not url:
        return None, None
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", url)
    if not m:
        return None, None
    return m.group(1), m.group(2).rstrip(".git")

def get_context(owner, repo, path, line, ctx=7):
    ck = cache_key(owner, repo, path)
    if not ck.exists():
        return None, None, None
    content = ck.read_text(encoding="utf-8", errors="replace")
    if content == "__NOT_FOUND__":
        return None, None, None
    lines = content.split("\n")
    if not line or line < 1:
        # No line — return first 60 lines (head)
        return lines[:60], 1, len(lines)
    lo = max(1, line - ctx)
    hi = min(len(lines), line + ctx)
    return lines[lo-1:hi], lo, len(lines)

src = json.load(open(ROOT / "top10_to_verify.json", encoding="utf-8"))

out = {"categories": []}
for cat in src["categories"]:
    cat_out = {"id": cat["id"], "name": cat["name"], "schema": cat["schema"], "findings": []}
    for i, f in enumerate(cat["findings"], 1):
        item = dict(f)
        item["_rank"] = i
        if f.get("file") and f.get("server_url"):
            owner, repo = parse_repo(f["server_url"])
            if owner:
                ctx_lines, start_line, total_lines = get_context(owner, repo, f["file"], f.get("line"))
                if ctx_lines is not None:
                    item["_owner"] = owner
                    item["_repo"] = repo
                    item["_context_start"] = start_line
                    item["_context_lines"] = ctx_lines
                    item["_total_lines"] = total_lines
                    if f.get("line"):
                        item["_permalink"] = f"https://github.com/{owner}/{repo}/blob/HEAD/{f['file']}#L{f['line']}"
                    else:
                        item["_permalink"] = f"https://github.com/{owner}/{repo}/blob/HEAD/{f['file']}"
                else:
                    item["_missing"] = True
                    item["_permalink"] = f"https://github.com/{owner}/{repo}/blob/HEAD/{f['file']}"
        cat_out["findings"].append(item)
    out["categories"].append(cat_out)

out_path = ROOT / "audit_context.json"
out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"Written: {out_path}")
print(f"Total: {sum(len(c['findings']) for c in out['categories'])} findings with context")
