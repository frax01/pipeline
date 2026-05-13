"""Redact real secret values in TOP10_VERIFIED.md and top10_to_verify.json.
Preserves the security signal (prefix + redaction marker) without leaking the actual key."""
import re
from pathlib import Path

ROOT = Path(r"C:/Users/francesco/Desktop/pipeline")

# Patterns to redact: (regex, replacement)
REDACTIONS = [
    # OpenAI sk-proj-* (variable length, real format)
    (re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"), "sk-proj-[REDACTED]"),
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "sk-ant-[REDACTED]"),
    # Google API key prefix AIzaSy + 33 chars
    (re.compile(r"AIzaSy[A-Za-z0-9_-]{33}"), "AIzaSy[REDACTED]"),
    # GitHub PAT
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "ghp_[REDACTED]"),
    (re.compile(r"ghs_[A-Za-z0-9]{36,}"), "ghs_[REDACTED]"),
    # Slack bot token
    (re.compile(r"xoxb-[A-Za-z0-9-]{20,}"), "xoxb-[REDACTED]"),
    # AWS access key
    (re.compile(r"AKIA[A-Z0-9]{16}"), "AKIA[REDACTED]"),
    # Long hex strings (>= 48 chars) often crypto secrets - the OBSIDIAN key
    (re.compile(r"dff0f5924469c2e541c758e14acb3d5a3f61f5da22f06f147fbafa8ff9d47868"), "[REDACTED-HEX64]"),
    (re.compile(r"4a1f2a537fe44d78a5c90b2a0b22d8a4ccaa1f3f6db820b850889f4de96e6ac8"), "[REDACTED-HEX64]"),
]

def redact(text):
    n = 0
    for rx, repl in REDACTIONS:
        new_text, count = rx.subn(repl, text)
        if count:
            print(f"  {rx.pattern[:60]}: {count} match")
            n += count
        text = new_text
    return text, n

for fname in ["TOP10_VERIFIED.md", "top10_to_verify.json"]:
    p = ROOT / fname
    print(f"\n=== {fname} ===")
    original = p.read_text(encoding="utf-8")
    redacted, n = redact(original)
    if n:
        p.write_text(redacted, encoding="utf-8")
        print(f"  -> {n} secrets redacted")
    else:
        print("  (no secrets found)")
