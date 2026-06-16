"""
LLM-analysis classifier for credential-leak findings.

Applies the rules documented in credential_leak_analysis.md to split
credential_leak_filtered.json into vp.json (True Positives) and fp.json
(False Positives).

Rules summary
-------------
Intentionally vulnerable / testing servers   -> FP
  - malicious_mcp, vulnerable-notes-mcp, IMCP
  - complete-mitre-attack-mcp-server, vertice-cyber (MITRE data dumps)
  - secure-mcp-gateway when file is bad_mcps/ or demo_pii_detection

INSECURE_CREDENTIAL_PERMISSIONS
  - file ends in .json                        -> FP  (MITRE/report data)
  - package.json with `chmod 755 .js`         -> FP  (CLI bit, not credential)

HARDCODED_CREDENTIALS
  - JWT payload role == "anon"                -> FP  (Supabase anon key)
  - AWS AKIA... key in an S3 pre-signed URL   -> FP
  - demo/placeholder secrets                   -> FP  (sk-abc123..., YOUR_, changeme, xxxxx, placeholder)

PLAINTEXT_STORAGE
  - stdout/stderr/print/console.log of a `token` variable in LLM streaming
                                               -> FP
  - SSE event writers that stream an LLM token -> FP
  - file ends in .json with structured dataset content
                                               -> FP
  - file is an OpenAPI/YAML spec with example `secret` literal
                                               -> FP
  - paths rooted in sample_workspace/, translation_workdir/cache/, data/repos/
                                               -> FP

Everything else is kept as VP.
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "credential_leak_filtered.json"
OUT_DIR = HERE / "llm_analysis"
OUT_VP = OUT_DIR / "vp.json"
OUT_FP = OUT_DIR / "fp.json"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def decode_jwt_payload(evidence: str) -> dict | None:
    m = re.search(r"eyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)", evidence)
    if not m:
        return None
    p = m.group(1)
    p += "=" * (-len(p) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(p).decode("utf-8", "replace"))
    except Exception:
        return None


INTENTIONAL_SERVERS = {
    # name -> optional file substring that must also match; None = any file
    "malicious_mcp": None,
    "vulnerable-notes-mcp": None,
    "IMCP": None,
    "complete-mitre-attack-mcp-server": None,
    "vertice-cyber": "mitre",
}


def is_intentional_vuln(f: dict) -> tuple[bool, str]:
    name = f.get("server_name", "")
    url = (f.get("github_url") or "").lower()
    path = (f.get("file") or "").lower()

    # Match repo segment in URL (github.com/<owner>/<repo>) case-insensitive,
    # but as a whole path segment so "IMCP" does not match "graphitiMCP".
    url_repo = url.rstrip("/").split("/")[-1] if url else ""

    for sname, file_hint in INTENTIONAL_SERVERS.items():
        if name == sname or url_repo == sname.lower():
            if file_hint is None or file_hint in path:
                return True, f"intentional_vuln_server:{sname}"
    # secure-mcp-gateway subset (bad_mcps / demo_pii_detection only)
    if name == "secure-mcp-gateway":
        if "bad_mcps/" in path or "demo_pii" in path or "credential_theft" in path:
            return True, "intentional_vuln_server:secure-mcp-gateway/bad_mcps"
    return False, ""


# -----------------------------------------------------------------------------
# Per-id classifiers
# -----------------------------------------------------------------------------
def classify_insecure_perms(f: dict) -> tuple[str, str]:
    path = (f.get("file") or "").lower()
    ev = f.get("evidence", "")
    if path.endswith("package.json"):
        return "FP", "insecure_perms_package_json_build_script"
    if path.endswith(".json"):
        return "FP", "insecure_perms_on_json_data_file"
    # `chmod 644` / `chmod 600` are *secure* permissions, not insecure.
    # The scanner flagged them only because the command contains 'chmod'.
    if re.search(r"chmod\s+(6[04]4|600|400|700|755)\b", ev):
        return "FP", "insecure_perms_secure_chmod_flagged"
    return "VP", "insecure_perms_kept"


AWS_PRESIGNED_HOSTS = ("amazonaws.com", "s3-")


def classify_hardcoded(f: dict) -> tuple[str, str]:
    provider = (f.get("filter_confidence") or "").split(":", 1)[-1].strip()
    ev = f.get("evidence", "")
    ev_low = ev.lower()
    path = (f.get("file") or "").lower()

    # Demo/placeholder detectors (any provider)
    demo_markers = (
        "abc123", "xxx", "placeholder", "changeme", "your_", "your-", "example",
        "<token>", "<key>", "xxxxxx", "0123456789",
    )
    # Only treat as demo if the evidence looks like a *sample* path/file
    sample_path = any(s in path for s in ("demo", "sample", "example", "test", "docs/"))
    if sample_path and any(m in ev_low for m in demo_markers):
        return "FP", "demo_placeholder_credential"

    if provider == "JWT Token":
        payload = decode_jwt_payload(ev)
        role = (payload or {}).get("role")
        if isinstance(role, str) and role == "anon":
            return "FP", "jwt_supabase_anon_key"
        return "VP", "jwt_non_anon"

    if provider == "AWS Access Key ID":
        if any(h in ev for h in AWS_PRESIGNED_HOSTS) and "AWSAccessKeyId=" in ev:
            return "FP", "aws_presigned_url_access_key"
        return "VP", "aws_access_key_literal"

    # Generic/OpenAI/Google/GitHub/Docker providers default to VP
    return "VP", f"hardcoded_{provider or 'unknown'}"


STREAM_TOKEN_PATTERNS = (
    re.compile(r"\bprocess\.stdout\.write\s*\(\s*token\b"),
    re.compile(r"\bsys\.stdout\.write\s*\(\s*token\b"),
    re.compile(r"\bstdout\.write\s*\(\s*token\b"),
    re.compile(r"\bprocess\.stdin\.write\s*\(\s*token\b"),
    re.compile(r"\bconsole\.log\s*\(\s*token\b"),
    re.compile(r"\bstdout\.write\s*\(\s*wrapColor\s*\(\s*c\s*,\s*token"),
    re.compile(r"\bstdout\.write\s*\(\s*chalk\.[a-z]+\s*\(\s*token"),
    re.compile(r"\bprint\s*\(\s*token\s*[,)]"),
    re.compile(r"sseEvent\s*\(\s*['\"]token['\"]"),
    re.compile(r"event:\s*session-token"),
    re.compile(r"data-finance:token"),
    re.compile(r"res\.write\s*\(\s*`?event:\s*token"),
)

DATA_JSON_HINTS = (
    "codeql.json", "mcpverse_data.json", "translation_db.json",
    "components.json", "dataset.json", "ai-api.json", "enterprise-attack.json",
    "lol_drivers.json", "discovery_cache", "exmaple_reports", "example_reports",
)
DATA_PATH_HINTS = (
    "sample_workspace/", "translation_workdir/cache/",
    "data/repos/", "tmp_packages/", "/venv/", "site-packages/",
    "/snippets/", "/cache/",
)


def classify_plaintext(f: dict) -> tuple[str, str]:
    ev = f.get("evidence", "")
    path = (f.get("file") or "").lower()

    for pat in STREAM_TOKEN_PATTERNS:
        if pat.search(ev):
            return "FP", "stream_token_output_not_credential"

    # package.json build/postinstall hooks never store real credentials;
    # they are build-tooling scripts (chmod, mkdir, scaffold empty config).
    if path.endswith("package.json"):
        return "FP", "plaintext_storage_package_json_build_script"

    # JSON data/report dumps
    if path.endswith(".json"):
        if any(h in path for h in DATA_JSON_HINTS) or any(h in path for h in DATA_PATH_HINTS):
            return "FP", "plaintext_storage_in_json_data_file"
        # keep only .json that *looks* like a real credential write
        if "token.write" in ev or "creds.to_json" in ev:
            return "VP", "plaintext_storage_credentials_json"
        return "FP", "plaintext_storage_in_json_data_file"

    # YAML / OpenAPI example bodies
    if path.endswith(".yml") or path.endswith(".yaml"):
        if "req.write" in ev and "secret" in ev.lower():
            return "FP", "plaintext_storage_openapi_example_body"

    # Paths that are obviously sample / cache / vendored
    if any(h in path for h in DATA_PATH_HINTS):
        return "FP", "plaintext_storage_sample_or_cache_path"

    # LangChain streaming_stdout callback module (always streaming)
    if "streaming_stdout" in path:
        return "FP", "stream_token_output_not_credential"

    return "VP", "plaintext_storage_credential_write"


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def classify(f: dict) -> tuple[str, str]:
    ok, reason = is_intentional_vuln(f)
    if ok:
        return "FP", reason
    vid = f.get("id")
    if vid == "INSECURE_CREDENTIAL_PERMISSIONS":
        return classify_insecure_perms(f)
    if vid == "HARDCODED_CREDENTIALS":
        return classify_hardcoded(f)
    if vid == "PLAINTEXT_STORAGE":
        return classify_plaintext(f)
    return "VP", "unknown_id_kept"


def main() -> None:
    with io.open(SRC, encoding="utf-8") as fh:
        src = json.load(fh)
    findings = src["findings"]

    vp, fp = [], []
    reasons: dict[str, int] = {}
    for f in findings:
        verdict, reason = classify(f)
        enriched = dict(f)
        enriched["llm_verdict"] = verdict
        enriched["llm_reason"] = reason
        (vp if verdict == "VP" else fp).append(enriched)
        reasons[reason] = reasons.get(reason, 0) + 1

    OUT_DIR.mkdir(exist_ok=True)

    def dump(path: Path, items: list, verdict: str) -> None:
        payload = {
            "category": src["category"],
            "llm_analysis_verdict": verdict,
            "source_filtered_file": SRC.name,
            "original_total": src.get("original_total"),
            "filter_kept_total": src.get("kept_total"),
            "llm_kept_total": len(items),
            "findings": items,
        }
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

    dump(OUT_VP, vp, "true_positive")
    dump(OUT_FP, fp, "false_positive")

    print(f"Total filtered:      {len(findings)}")
    print(f"True positives (VP): {len(vp)}")
    print(f"False positives (FP): {len(fp)}")
    print(f"VP rate: {len(vp)/len(findings)*100:.1f}%")
    print()
    print("Breakdown by reason:")
    for r, c in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"  {c:4d}  {r}")


if __name__ == "__main__":
    main()
