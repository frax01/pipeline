"""
Stage 2A — 3-bucket classifier for credential-leak findings.

Buckets:
  HC-FP  → high-confidence False Positive  (regole molto specifiche, FP certo)
  HC-VP  → high-confidence True Positive   (regole molto specifiche, VP certo)
  UNCERTAIN → giudizio semantico richiesto  (va analizzato dall'LLM in chat)

Output (in llm_analysis/):
  hc_fp.json      — FP certi (nessuna chiamata LLM)
  hc_vp.json      — VP certi (nessuna chiamata LLM)
  uncertain.json  — da analizzare con LLM in chat
"""

from __future__ import annotations
import base64, io, json, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC  = HERE / "credential_leak_filtered.json"
OUT  = HERE / "llm_analysis"

# ─── helpers ────────────────────────────────────────────────────────────────

def decode_jwt(ev: str) -> dict | None:
    m = re.search(r"eyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)", ev)
    if not m: return None
    p = m.group(1) + "=" * (-len(m.group(1)) % 4)
    try:    return json.loads(base64.urlsafe_b64decode(p).decode("utf-8", "replace"))
    except: return None

def is_env_file(path: str) -> bool:
    name = path.lower().split("/")[-1]
    return name in (".env", ".env.local", ".env.production", ".env.development",
                    ".env.example.filled", ".env.real") or \
           (name.startswith(".env.") and "example" not in name and "sample" not in name and "template" not in name)

# ─── HC-FP rules ─────────────────────────────────────────────────────────────

INTENTIONAL_VULN = {
    "malicious_mcp": None,
    "vulnerable-notes-mcp": None,
    "complete-mitre-attack-mcp-server": None,
    "vertice-cyber": "mitre",
}

STREAM_PATS = [
    # LLM streaming tokens
    re.compile(r"\bprocess\.stdout\.write\s*\(\s*token\b"),
    re.compile(r"\bsys\.stdout\.write\s*\(\s*token\b"),
    re.compile(r"\bstdout\.write\s*\(\s*(?:token|wrapColor|chalk\.[a-z]+\s*\()\b"),
    re.compile(r"\bprocess\.stdin\.write\s*\(\s*token\b"),
    re.compile(r"sseEvent\s*\(\s*['\"]token['\"]"),
    re.compile(r"event:\s*session-token"),
    re.compile(r"data-finance:token"),
    # stdin/socket passthrough to subprocess (SSH/Docker/Telnet/Serial) — not storage
    re.compile(r"\bstdin\.write\b"),
    re.compile(r"\bstream\.write\s*\("),
    re.compile(r"\bsession\.stream\.write\b"),
    re.compile(r"\bproc\.stdin\.write\b"),
    re.compile(r"\bsocket\?\.write\b|\bsocket\.write\b"),
    re.compile(r"\bconnection\.shell\.write\b"),
    re.compile(r"\bport\.write\b"),
    re.compile(r"\bwriter\.write\s*\(.*password.*encode\b", re.IGNORECASE),  # UPS NUT protocol
    # Help text / CLI usage messages printed to stdout (not credential storage)
    re.compile(r"process\.stdout\.write\s*\(`[^`]*(?:--password|PASSWORD)[^`]*`\)"),
    # res.write for SSE/HTTP streaming (not disk storage)
    re.compile(r"\bres\.write\s*\(\s*`data:"),
    re.compile(r"\bres\.write\s*\(\s*`event:"),
    re.compile(r"Token limit exceeded"),
    # Lexical/search index writers (token = word, not credential)
    re.compile(r"chunk_id.*token.*term_freq", re.IGNORECASE),
    # Django management command stdout (just printing status, not storing)
    re.compile(r"self\.stdout\.write\s*\(\s*self\.style\.(SUCCESS|ERROR|WARNING)"),
    # Commented-out code
    re.compile(r"^\s*#"),
    # ORM write (Odoo self.write({...})) — database ORM, not file
    re.compile(r"\bself\.write\s*\(\s*\{"),
    # Minified JS libraries (contain 'password'/'token' as variable names in bundle)
    re.compile(r"\"object\"==typeof exports"),
    re.compile(r"!function\s*\(e,t\)"),
]

# Vault write is storing into a proper secret manager, not plaintext FS
VAULT_WRITE_PAT = re.compile(r"vaultClient\.write|vault\.write\s*\(", re.IGNORECASE)

DATA_JSON = ("codeql.json","mcpverse_data.json","translation_db.json","components.json",
             "dataset.json","ai-api.json","enterprise-attack.json","lol_drivers.json",
             "techniques.json")
DATA_PATHS = ("sample_workspace/","translation_workdir/cache/","data/repos/",
              "tmp_packages/","/venv/","site-packages/","/snippets/")

def hc_fp(f: dict) -> tuple[bool, str]:
    name = f.get("server_name","")
    url  = (f.get("github_url") or "").lower()
    path = (f.get("file") or "").lower()
    ev   = f.get("evidence","")
    vid  = f.get("id","")

    # intentional vuln / honeypot
    repo = url.rstrip("/").split("/")[-1]
    for sname, hint in INTENTIONAL_VULN.items():
        if name == sname or repo == sname.lower():
            if hint is None or hint in path:
                return True, f"hc_fp:intentional_vuln:{sname}"
    if name == "secure-mcp-gateway" and ("bad_mcps/" in path or "demo_pii" in path or "credential_theft" in path):
        return True, "hc_fp:intentional_vuln:secure-mcp-gateway/bad_mcps"

    # JWT Supabase anon
    if f.get("filter_confidence","") == "provider:JWT Token":
        payload = decode_jwt(ev) or {}
        if isinstance(payload.get("role"), str) and payload["role"] == "anon":
            return True, "hc_fp:jwt_supabase_anon"

    # INSECURE_CREDENTIAL_PERMISSIONS
    if vid == "INSECURE_CREDENTIAL_PERMISSIONS":
        if path.endswith("package.json"):
            return True, "hc_fp:insecure_perms_package_json_build"
        if path.endswith(".json"):
            return True, "hc_fp:insecure_perms_json_data_file"
        if re.search(r"chmod\s+(6[04]4|600|400|700|755)\b", ev):
            return True, "hc_fp:insecure_perms_secure_chmod"

    # PLAINTEXT_STORAGE
    if vid == "PLAINTEXT_STORAGE":
        if path.endswith("package.json"):
            return True, "hc_fp:plaintext_package_json_build"
        for pat in STREAM_PATS:
            if pat.search(ev):
                return True, "hc_fp:stream_token_llm_output"
        if path.endswith(".json") and (any(h in path for h in DATA_JSON) or any(h in path for h in DATA_PATHS)):
            return True, "hc_fp:plaintext_json_data_file"
        if (path.endswith(".yml") or path.endswith(".yaml")) and "req.write" in ev and "secret" in ev.lower():
            return True, "hc_fp:plaintext_openapi_example"
        if any(h in path for h in DATA_PATHS):
            return True, "hc_fp:plaintext_vendored_path"
        # Vault (HashiCorp Vault) is a proper secret manager — not plaintext storage
        if VAULT_WRITE_PAT.search(ev):
            return True, "hc_fp:plaintext_vault_secret_manager"
        # json/yaml data files not caught above (Stitch Flow, STABILITY, etc.)
        if path.endswith(".json") or path.endswith(".yaml") or path.endswith(".yml"):
            return True, "hc_fp:plaintext_data_file"

    # Credentials inside commented-out code (Python # or JS //) → FP
    if vid == "HARDCODED_CREDENTIALS":
        ev_stripped = ev.strip()
        if ev_stripped.startswith("#") or ev_stripped.startswith("//") or ev_stripped.startswith("*"):
            return True, "hc_fp:commented_out_code"

    # AWS pre-signed URL
    if f.get("filter_confidence","") == "provider:AWS Access Key ID":
        if ("amazonaws.com" in ev or "s3" in ev.lower()) and "AWSAccessKeyId=" in ev:
            return True, "hc_fp:aws_presigned_url"

    return False, ""

# ─── HC-VP rules ─────────────────────────────────────────────────────────────

# Patterns where format alone almost guarantees a real credential
HC_VP_PROVIDERS = {
    "provider:GitHub PAT (classic)",
    "provider:Docker PAT",
    "provider:GitHub PAT (fine-grained)",
    "provider:GitLab PAT",
    "provider:Stripe Secret Key (live)",
    "provider:Private Key Header",
    "provider:MongoDB URI with creds",
    "provider:PostgreSQL URI with creds",
    "provider:MySQL URI with creds",
    "provider:Redis URI with creds",
    # Google API Key (AIza + 35 chars) is very specific; first filter already
    # eliminated firebase/analytics keys, so what remains is VP.
    "provider:Google API Key",
    # OpenAI sk- (40-60 chars); first filter already eliminated demo patterns.
    "provider:OpenAI Legacy Key",
    # AWS Access Key ID literal (non-presigned URLs were already caught as HC-FP)
    "provider:AWS Access Key ID",
}

GOOGLE_OAUTH_WRITE = re.compile(
    r"(?:creds|credentials|token)\s*(?:_file)?\s*\.(?:write|to_json)\s*\("
    r"|fs\.writeFileSync.*credentials"
    r"|token_file\.write\s*\(",
    re.IGNORECASE,
)

def hc_vp(f: dict) -> tuple[bool, str]:
    path = (f.get("file") or "").lower()
    ev   = f.get("evidence","")
    conf = f.get("filter_confidence","")
    vid  = f.get("id","")

    # Provider with near-zero FP rate (format is too specific to be demo)
    if conf in HC_VP_PROVIDERS:
        return True, f"hc_vp:format_specific:{conf}"

    # JWT with service_role (Supabase secret key)
    if conf == "provider:JWT Token":
        payload = decode_jwt(ev) or {}
        role = payload.get("role","")
        if isinstance(role, str) and role in ("service_role", "admin", "service"):
            return True, "hc_vp:jwt_service_role"

    # Any provider key sitting inside a .env file
    if is_env_file(path) and vid == "HARDCODED_CREDENTIALS":
        return True, "hc_vp:key_in_env_file"

    # Google OAuth token write (creds.to_json() / token.write / token_file.write)
    if vid == "PLAINTEXT_STORAGE" and GOOGLE_OAUTH_WRITE.search(ev):
        # exclude if in a data / sample path
        if not any(h in path for h in DATA_PATHS) and not path.endswith(".json"):
            return True, "hc_vp:google_oauth_token_write"

    # writeFileSync/writeFile with credential variable → plaintext storage on disk (VP)
    if vid == "PLAINTEXT_STORAGE" and re.search(r"writeFileSync|writeFile\b", ev, re.IGNORECASE):
        if not any(h in path for h in DATA_PATHS) and not path.endswith(".json"):
            return True, "hc_vp:plaintext_writefile_credential"

    return False, ""

# ─── main ───────────────────────────────────────────────────────────────────

def classify(f: dict) -> tuple[str, str]:
    ok, r = hc_fp(f)
    if ok: return "HC-FP", r
    ok, r = hc_vp(f)
    if ok: return "HC-VP", r
    return "UNCERTAIN", "needs_llm_judgment"

def main() -> None:
    with io.open(SRC, encoding="utf-8") as fh:
        src = json.load(fh)
    findings = src["findings"]

    hc_fp_list, hc_vp_list, unc_list = [], [], []
    for f in findings:
        bucket, reason = classify(f)
        enriched = dict(f, llm_bucket=bucket, bucket_reason=reason)
        if   bucket == "HC-FP":    hc_fp_list.append(enriched)
        elif bucket == "HC-VP":    hc_vp_list.append(enriched)
        else:                       unc_list.append(enriched)

    OUT.mkdir(exist_ok=True)

    def dump(path: Path, items: list, meta: dict) -> None:
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump({**meta, "total": len(items), "findings": items},
                      fh, ensure_ascii=False, indent=2)

    base_meta = {"category": src["category"],
                 "original_total": src.get("original_total"),
                 "filter_kept_total": src.get("kept_total")}

    dump(OUT / "hc_fp.json",    hc_fp_list,  {**base_meta, "bucket": "HC-FP"})
    dump(OUT / "hc_vp.json",    hc_vp_list,  {**base_meta, "bucket": "HC-VP"})
    dump(OUT / "uncertain.json", unc_list,   {**base_meta, "bucket": "UNCERTAIN"})

    total = len(findings)
    print(f"{'─'*45}")
    print(f"  Total filtered:   {total:4d}")
    print(f"  HC-FP  (certo):   {len(hc_fp_list):4d}  ({len(hc_fp_list)/total*100:.1f}%)")
    print(f"  HC-VP  (certo):   {len(hc_vp_list):4d}  ({len(hc_vp_list)/total*100:.1f}%)")
    print(f"  UNCERTAIN (LLM):  {len(unc_list):4d}  ({len(unc_list)/total*100:.1f}%)")
    print(f"{'─'*45}")
    print()

    from collections import Counter
    print("HC-FP reasons:")
    for r,c in Counter(x["bucket_reason"] for x in hc_fp_list).most_common():
        print(f"  {c:3d}  {r}")
    print()
    print("HC-VP reasons:")
    for r,c in Counter(x["bucket_reason"] for x in hc_vp_list).most_common():
        print(f"  {c:3d}  {r}")
    print()
    print("UNCERTAIN by id + filter_confidence:")
    for r,c in Counter(f"{x['id']}|{x.get('filter_confidence','')}" for x in unc_list).most_common():
        print(f"  {c:3d}  {r}")

if __name__ == "__main__":
    main()
