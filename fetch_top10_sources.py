"""Fetch GitHub source files for top 10 per category.
Uses raw.githubusercontent.com (no auth, no rate-limit on most repos).
Cache: top10_cache/<owner>__<repo>__<safe_path>.txt
NOT a classifier — just downloads source so the human can read it."""

import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(r"C:/Users/francesco/Desktop/pipeline")
CACHE = ROOT / "top10_cache"
CACHE.mkdir(exist_ok=True)

USER_AGENT = "Mozilla/5.0 (manual-audit-fetch/1.0)"

# Branches to try in order
BRANCHES = ["HEAD", "main", "master"]

def parse_repo(url):
    if not url:
        return None, None
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", url)
    if not m:
        return None, None
    owner, repo = m.group(1), m.group(2).rstrip(".git")
    return owner, repo

def cache_key(owner, repo, path):
    safe = path.replace("/", "__").replace("\\", "__").replace(":", "_")
    return CACHE / f"{owner}__{repo}__{safe}"

def fetch_raw(owner, repo, path):
    """Try branches until one works. Return text or None."""
    ck = cache_key(owner, repo, path)
    if ck.exists():
        try:
            return ck.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
    for br in BRANCHES:
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{br}/{path}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = r.read().decode("utf-8", errors="replace")
                ck.write_text(data, encoding="utf-8")
                return data
        except urllib.error.HTTPError as e:
            if e.code in (404, 400):
                continue
            return None
        except Exception:
            return None
    # Mark not-found so we don't retry
    ck.write_text("__NOT_FOUND__", encoding="utf-8")
    return None

def main():
    src = json.load(open(ROOT / "top20_to_verify.json", encoding="utf-8"))
    fetched, missing = 0, 0
    for cat in src["categories"]:
        cat_id = cat["id"]
        name = cat["name"]
        for i, f in enumerate(cat["findings"], 1):
            path = f.get("file")
            if not path:
                continue  # tool description, no source file
            owner, repo = parse_repo(f.get("server_url"))
            if not owner:
                continue
            print(f"[{cat_id:2d}.{i:2d}] {owner}/{repo}/{path} ... ", end="", flush=True)
            content = fetch_raw(owner, repo, path)
            if content and content != "__NOT_FOUND__":
                print(f"OK ({len(content)} chars)")
                fetched += 1
            else:
                print("MISSING")
                missing += 1
    print(f"\nFetched: {fetched}, Missing: {missing}")

if __name__ == "__main__":
    main()
