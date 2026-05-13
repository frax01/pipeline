"""Retry fetching missing source files with alternative paths."""
import json
import urllib.request
import re
from pathlib import Path

CACHE = Path(r"C:/Users/francesco/Desktop/pipeline/top10_cache")

# Manual renames (repo name truncated in vp.json)
RETRIES = {
    "shettysaish20/Telegram-AI-MCP-Assistant-Bo": "shettysaish20/Telegram-AI-MCP-Assistant-Bot",
    "noflevi10root/mcp-tes": "noflevi10root/mcp-test",
}

def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "audit/1.0"})
        return urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
    except Exception:
        return None

def cache_key(owner, repo, path):
    safe = path.replace("/", "__").replace("\\", "__")
    return CACHE / f"{owner}__{repo}__{safe}"

src = json.load(open(r"C:/Users/francesco/Desktop/pipeline/top20_to_verify.json", encoding="utf-8"))

recovered = 0
for cat in src["categories"]:
    for f in cat["findings"]:
        path = f.get("file")
        url = f.get("server_url", "") or ""
        if not path:
            continue
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", url)
        if not m:
            continue
        owner = m.group(1)
        repo = m.group(2).rstrip(".git")
        ck = cache_key(owner, repo, path)
        if ck.exists():
            txt = ck.read_text(encoding="utf-8", errors="replace")
            if txt != "__NOT_FOUND__":
                continue
        key = f"{owner}/{repo}"
        success = False
        # Try corrected repo names
        if key in RETRIES:
            o2, r2 = RETRIES[key].split("/")
            for br in ["HEAD", "main", "master", "develop"]:
                u = f"https://raw.githubusercontent.com/{o2}/{r2}/{br}/{path}"
                c = fetch(u)
                if c:
                    ck.write_text(c, encoding="utf-8")
                    print(f"RECOVERED rename: {key} -> {RETRIES[key]} ({len(c)} chars)")
                    recovered += 1
                    success = True
                    break
        if success:
            continue
        # Try alt path for dist/
        if "dist/" in path:
            for alt in [path.replace("dist/src/", "src/"), path.replace("dist/", "src/")]:
                for br in ["HEAD", "main", "master"]:
                    u = f"https://raw.githubusercontent.com/{owner}/{repo}/{br}/{alt}"
                    c = fetch(u)
                    if c:
                        ck.write_text(c, encoding="utf-8")
                        print(f"RECOVERED alt: {owner}/{repo}/{path} -> {alt} ({len(c)} chars)")
                        recovered += 1
                        success = True
                        break
                if success:
                    break
        if success:
            continue
        # Try the .ts -> .js or vice-versa
        if path.endswith(".ts"):
            alt = path[:-3] + ".js"
            for br in ["HEAD", "main", "master"]:
                u = f"https://raw.githubusercontent.com/{owner}/{repo}/{br}/{alt}"
                c = fetch(u)
                if c:
                    ck.write_text(c, encoding="utf-8")
                    print(f"RECOVERED ext: {owner}/{repo}/{path} -> {alt} ({len(c)} chars)")
                    recovered += 1
                    success = True
                    break

print(f"\nRecovered total: {recovered}")
