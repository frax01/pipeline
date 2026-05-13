#!/usr/bin/env python3
"""
stage2c_auto_audit.py — Stage 2C: classificazione automatica VP-C / VP-L / VP-D / FP

Riapplica la stessa euristica del MANUAL_AUDIT_REPORT.md (537 finding) ma
automatizzata via LLM + fetch del codice sorgente reale da GitHub.

Workflow per ogni finding:
  1. Load finding da vp.json
  2. Fetch del file sorgente da raw.githubusercontent.com (cached on disk)
  3. Estrai context window ±30 righe attorno alla `line`
  4. Build prompt strutturato con taxonomia VP-C/VP-L/VP-D/FP
  5. Chiamata Claude API con tool_use per output JSON validato
  6. Cache verdetto in stage2c_cache/llm_verdicts.json
  7. Se confidence < 70: re-prompt con full file content (no estimates)
  8. Aggregato finale per categoria + report Markdown + diff vs ground truth

Esecuzione:
    py -X utf8 stage2c_auto_audit.py --all                # tutti i 537
    py -X utf8 stage2c_auto_audit.py --category sql-injection
    py -X utf8 stage2c_auto_audit.py --category sql-injection --limit 5
    py -X utf8 stage2c_auto_audit.py --report-only        # rigenera solo il report

Richiede:
    export ANTHROPIC_API_KEY="sk-ant-..."

Output:
    stage2c_cache/github/<sha>.txt                       # cache file sorgenti
    stage2c_cache/llm_verdicts.json                      # cache verdetti (idempotente)
    stage2c_output/verdicts.json                         # verdetti finali strutturati
    stage2c_output/auto_audit_report.md                  # report Markdown
    stage2c_output/comparison_vs_manual.md               # confronto vs MANUAL_AUDIT_REPORT
"""

import argparse
import hashlib
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.stdout.reconfigure(encoding="utf-8")

# ---------------------------------------------------------------------------
# Configurazione: sample identico a MANUAL_AUDIT_REPORT.md (537 finding)
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "analysisAllData"
CACHE_DIR = BASE_DIR / "stage2c_cache"
OUTPUT_DIR = BASE_DIR / "stage2c_output"
GITHUB_CACHE = CACHE_DIR / "github"
LLM_CACHE_FILE = CACHE_DIR / "llm_verdicts.json"

# Meta-category  ->  list of (vp.json path, sample_size or None per intero universo)
# Allineato alla §5.1 di THREAT_ANALYSIS_REPORT.md, ognuna delle 17 minacce
# raccoglie i finding da TUTTI i framework che vi contribuiscono.
# Target: 100 finding per meta-categoria se possibile, oppure 100% se <100 totale.
SAMPLE_SCHEME = {
    "1.sql-injection": [
        ("0_tool_mcp_guard/sql-injection-static/filtered/llm_analysis/vp.json", 100),
    ],
    "2.dangerous-capabilities": [
        ("0_tool_mcp_security_scan/dangerous-capabilities/filtered/llm_analysis/vp.json", 50),
        ("0_tool_mcp_guard/dangerous-tool-handler-static/filtered/llm_analysis/vp.json", 50),
    ],
    "3.credential-leak": [
        ("0_tool_mcp_watch/credential-leak/filtered/llm_analysis/vp.json", 50),
        ("0_tool_mcp_guard/hardcoded-credential-static/filtered/llm_analysis/vp.json", 50),
    ],
    "4.ssrf": [
        ("0_tool_mcp_guard/ssrf-static/filtered/llm_analysis/vp.json", 100),
    ],
    "5.untrusted-content": [
        ("0_tool_mcp_scan/server-level/filtered/llm_analysis/vp.json", 100),
    ],
    "6.path-traversal": [
        ("0_tool_mcp_guard/path-traversal-static/filtered/llm_analysis/vp.json", None),       # 23 ALL
        ("0_tool_mcp_guard/path-traversal-fuzzing/filtered/llm_analysis/vp.json", 72),         # primi 72 (23+72+5=100)
        ("0_tool_mcp_security_scan/path-traversal/filtered/llm_analysis/vp.json", None),       # 5 ALL
    ],
    "7.command-injection": [
        ("0_tool_mcp_guard/command-injection-static/filtered/llm_analysis/vp.json", None),     # 21 ALL
        ("0_tool_mcp_guard/command-injection-fuzzing/filtered/llm_analysis/vp.json", 77),      # primi 77 (21+77+2=100)
        ("0_tool_mcp_guard/command-execution-fuzzing/filtered/llm_analysis/vp.json", None),    # 2 ALL
    ],
    "8.code-injection": [
        ("0_tool_mcp_guard/code-injection-static/filtered/llm_analysis/vp.json", 64),          # 64 + 36 = 100
        ("0_tool_mcp_guard/code-injection-fuzzing/filtered/llm_analysis/vp.json", None),       # 36 ALL
    ],
    "9.input-validation": [
        ("0_tool_mcp_watch/input-validation/filtered/llm_analysis/vp.json", 50),
        ("0_tool_mcp_security_scan/input-validation/filtered/llm_analysis/vp.json", 50),
    ],
    "10.protocol-violation": [
        ("0_tool_mcp_watch/protocol-violation/filtered/llm_analysis/vp.json", 79),             # 79 ALL
        ("0_tool_mcp_guard/protocol-invalid-jsonrpc-version/filtered/llm_analysis/vp.json", 21),  # primi 21
    ],
    "11.prompt-injection": [
        ("0_tool_mcp_scan/tool-level/filtered/llm_analysis/vp.json", None),                    # 36 ALL
        ("0_tool_mcp_guard/prompt-injection-static/filtered/llm_analysis/vp.json", None),      # 16 ALL
        ("0_tool_mcp_shield/hidden-instructions/llm_analysis/vp.json", None),                  # 4 ALL
    ],
    "12.insecure-deserialization": [
        ("0_tool_mcp_guard/insecure-deserialization-static/filtered/llm_analysis/vp.json", None),  # 31 ALL
    ],
    "13.sensitive-file-access": [
        ("0_tool_mcp_shield/sensitive-file-access/llm_analysis/vp.json", None),                # 11 ALL
        ("0_tool_mcp_security_scan/sensitive-file-access/filtered/llm_analysis/vp.json", None),  # 5 ALL
    ],
    "14.sensitive-info-disclosure": [
        ("0_tool_mcp_guard/information-disclosure-fuzzing/filtered/llm_analysis/vp.json", None),   # 4 ALL
        ("0_tool_mcp_guard/sensitive-info-disclosed-fuzzing/filtered/llm_analysis/vp.json", None), # 1 ALL
        ("0_tool_mcp_guard/protocol-information-disclosure/filtered/llm_analysis/vp.json", None), # 4 ALL
    ],
    "15.access-control": [
        ("0_tool_mcp_watch/access-control/filtered/llm_analysis/vp.json", None),               # 7 ALL
    ],
    "16.data-exfiltration": [
        ("0_tool_mcp_watch/data-exfiltration/filtered/llm_analysis/vp.json", None),            # 2 ALL
    ],
    "17.tool-shadowing": [
        ("0_tool_mcp_shield/shadowing-detected/llm_analysis/vp.json", None),                   # 1 ALL
    ],
}

# Backend default: ollama (locale, gratuito). Alternative: anthropic, gemini, groq.
DEFAULT_BACKEND = "ollama"
DEFAULT_MODEL_CLAUDE = "claude-sonnet-4-5"
DEFAULT_MODEL_OLLAMA = "llama3.1:latest"
DEFAULT_MODEL_GEMINI = "gemini-2.0-flash"
DEFAULT_MODEL_GROQ = "llama-3.3-70b-versatile"

LOW_CONFIDENCE_THRESHOLD = 70          # sotto questo livello -> re-prompt con full file
MAX_CONTEXT_LINES = 30                 # finestra ± attorno alla line del finding

# Endpoint API
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_VERSION = "2023-06-01"
OLLAMA_API_URL = "http://localhost:11434/api/generate"
GEMINI_API_URL_TPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# ---------------------------------------------------------------------------
# Taxonomia & prompt
# ---------------------------------------------------------------------------

TAXONOMY = """
Classifica ogni finding in una di queste 4 categorie:

VP-C (Vero Positivo Confermato): Vulnerabilita' SFRUTTABILE sul codice attuale.
   La variabile interpolata/usata proviene da input attaccante non validato
   (parametro tool MCP, URI di resource, args HTTP, payload JSON-RPC) e raggiunge
   un sink pericoloso senza mitigazione effettiva.
   Esempio: cursor.execute(f"SELECT * FROM {table}") dove `table` viene da read_resource URI senza validazione.

VP-L (Vero Positivo Latente / by-design): Pattern sintaticamente corretto ma NON SFRUTTABILE oggi.
   Possibili motivi: (a) tutti i caller passano valori hardcoded; (b) sorgente
   fidata (sqlite_master, SHOW TABLES, env var server-set); (c) il server espone
   gia' la stessa capability come tool dichiarato (es. DB-MCP con execute_query);
   (d) tool offensivo intenzionalmente esposto (sec-mimikatz, sec-rubeus, aws-pentest);
   (e) server honeypot dichiarato (vulnerable-notes, IMCP).
   Esempio: pickle.loads(row[0]) dove row proviene da SQLite locale del server.

VP-D (Vero Positivo Debole): Segnale corretto ma severita' bassa o limitata.
   Esempio: SSRF con `fetch(\\`${API_BASE}/users/${params.id}\\`)` — params.id
   controllato attaccante ma API_BASE hardcoded su SaaS noto, quindi non e' SSRF
   globale ma solo path manipulation su API specifico.

FP (Falso Positivo): Pattern matchato ma codice benigno.
   Esempi noti:
   - regex `.exec()` JavaScript confuso con shell exec
   - Firebase web config (apiKey pubblica per design)
   - Chrome CrUX API public key
   - File `.d.ts` TypeScript type declarations (no runtime)
   - Codice vendored di estensioni (debugpy, ms-python, winappdbg)
   - Test/fixture file
   - OAuth public client config in directory `public/`
"""

# ---------------------------------------------------------------------------
# GitHub fetcher con cache locale
# ---------------------------------------------------------------------------

def _safe_filename(s: str) -> str:
    """Hash stabile per usare un identificatore come nome file."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:40]


def parse_github_url(server_url: str):
    """Estrai (owner, repo) da https://github.com/OWNER/REPO."""
    if not server_url:
        return None, None
    m = re.match(r"https://github\.com/([^/]+)/([^/?#]+)", server_url)
    if not m:
        return None, None
    return m.group(1), m.group(2).rstrip(".git")


def github_fetch(server_url: str, file_path: str) -> str:
    """Fetch raw GitHub file con caching disk-persistent.

    Tenta `main` e `master` come branch. Restituisce stringa vuota se 404 su entrambi
    o errore di rete (per evitare retry costanti, scrive comunque un marker vuoto).
    """
    if not server_url or not file_path:
        return ""
    owner, repo = parse_github_url(server_url)
    if not owner or not repo:
        return ""

    GITHUB_CACHE.mkdir(parents=True, exist_ok=True)
    cache_key = _safe_filename(f"{owner}/{repo}/{file_path}")
    cache_file = GITHUB_CACHE / f"{cache_key}.txt"

    if cache_file.exists():
        return cache_file.read_text(encoding="utf-8", errors="replace")

    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
        try:
            req = Request(url, headers={"User-Agent": "stage2c-audit/1.0"})
            with urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8", errors="replace")
                cache_file.write_text(content, encoding="utf-8")
                return content
        except HTTPError as e:
            if e.code in (403, 429):
                # Rate limit: aspetta e riprova una volta
                time.sleep(2)
                try:
                    with urlopen(req, timeout=15) as resp:
                        content = resp.read().decode("utf-8", errors="replace")
                        cache_file.write_text(content, encoding="utf-8")
                        return content
                except Exception:
                    pass
            # 404 -> prova prossimo branch
            continue
        except (URLError, TimeoutError, OSError):
            continue

    # Marker negativo: scrivi vuoto per non ri-fetchare
    cache_file.write_text("", encoding="utf-8")
    return ""


def github_repo_description(server_url: str) -> str:
    """Fetch della repo description via GitHub API REST (cached)."""
    owner, repo = parse_github_url(server_url)
    if not owner or not repo:
        return ""
    cache_key = _safe_filename(f"repo-desc:{owner}/{repo}")
    cache_file = GITHUB_CACHE / f"{cache_key}.txt"
    if cache_file.exists():
        return cache_file.read_text(encoding="utf-8", errors="replace")
    url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        headers = {"User-Agent": "stage2c-audit/1.0", "Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(url, headers=headers)
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        desc = data.get("description") or ""
        cache_file.write_text(desc, encoding="utf-8")
        return desc
    except Exception:
        cache_file.write_text("", encoding="utf-8")
        return ""


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------

def extract_context(source: str, line_num, window=MAX_CONTEXT_LINES) -> str:
    """Estrai ±window righe attorno a line_num, con numeri di riga."""
    if not source:
        return "(file non disponibile su GitHub)"
    lines = source.splitlines()
    if not line_num:
        return "\n".join(f"{i+1:6d}: {l}" for i, l in enumerate(lines[:80]))
    try:
        line_num = int(line_num)
    except (TypeError, ValueError):
        return "\n".join(f"{i+1:6d}: {l}" for i, l in enumerate(lines[:80]))
    start = max(0, line_num - 1 - window)
    end = min(len(lines), line_num + window)
    out = []
    for i, l in enumerate(lines[start:end], start=start):
        marker = " >> " if (i + 1) == line_num else "    "
        out.append(f"{marker}{i+1:6d}: {l}")
    return "\n".join(out)


def normalize_finding(category_key: str, raw: dict) -> dict:
    """Normalizza i finding tra framework (schema diversi)."""
    server_url = raw.get("server_url") or raw.get("github_url") or ""
    server_name = raw.get("server_name") or ""
    file_path = raw.get("file") or ""
    line = raw.get("line") or 0
    # mcp-guard: descrizione contiene "Code: <snippet>" e a volte la riga
    description = raw.get("description") or raw.get("message") or raw.get("evidence") or ""
    # Mcp-watch: evidence diretto
    evidence = raw.get("evidence") or ""
    # mcp-scan tool-level: tool_description e tool_name
    tool_name = raw.get("tool_name") or ""
    tool_description = raw.get("tool_description") or ""
    # mcp-scan W015 / scan E001: extra_data
    extra = raw.get("extra_data") or {}
    extra_reason = extra.get("reason") or ""
    extra_example = extra.get("example") or ""

    # Estrai "Code: <snippet>" dalla description di mcp-guard
    code_snippet = ""
    if "Code:" in description:
        code_snippet = description.split("Code:", 1)[1].strip()
    # Riga estratta da pattern "at line N"
    if not line:
        m = re.search(r"at line (\d+)", description)
        if m:
            line = int(m.group(1))

    return {
        "category": category_key,
        "server_url": server_url,
        "server_name": server_name,
        "file": file_path,
        "line": line,
        "evidence": evidence or description,
        "code_snippet": code_snippet,
        "tool_name": tool_name,
        "tool_description": tool_description,
        "framework_reason": extra_reason,
        "framework_example": extra_example,
        "_hc_verdict": raw.get("_hc_verdict") or "",
        "_hc_reason": raw.get("_hc_reason") or "",
    }


# ---------------------------------------------------------------------------
# LLM client — multi-backend (anthropic / ollama / gemini / groq)
# ---------------------------------------------------------------------------

# Tutti i backend devono restituire un dict con almeno {verdict, confidence, reasoning, key_quote, ...}
# Wrapper unico per chiamare il backend selezionato.

def llm_classify(prompt: str, system: str, backend: str, model: str) -> dict:
    """Dispatcher che chiama il backend selezionato e ritorna sempre un dict normalizzato."""
    if backend == "anthropic":
        api_resp = _anthropic_call(
            messages=[{"role": "user", "content": prompt}],
            system=system, model=model
        )
        return parse_tool_response(api_resp)
    if backend == "ollama":
        return _ollama_call(prompt, system, model)
    if backend == "gemini":
        return _gemini_call(prompt, system, model)
    if backend == "groq":
        return _groq_call(prompt, system, model)
    raise ValueError(f"Backend sconosciuto: {backend}")


_JSON_RE = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.S)

def _extract_json(text: str) -> dict:
    """Estrai il primo JSON object dal testo (utile per Ollama/Gemini/Groq che ritornano markdown+JSON)."""
    if not text:
        return {}
    # Try direct
    try:
        return json.loads(text.strip())
    except Exception:
        pass
    # Try fenced ```json ... ```
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    # Try first {...} balanced
    for match in _JSON_RE.finditer(text):
        try:
            return json.loads(match.group(0))
        except Exception:
            continue
    return {}


def _normalize_verdict(d: dict) -> dict:
    """Normalizza le chiavi del verdict (alcuni LLM usano varianti)."""
    out = {}
    out["verdict"] = (d.get("verdict") or d.get("classification") or "UNKNOWN").upper().strip()
    try:
        out["confidence"] = int(d.get("confidence", 0))
    except (TypeError, ValueError):
        out["confidence"] = 0
    out["reasoning"] = d.get("reasoning") or d.get("reason") or ""
    out["key_quote"] = d.get("key_quote") or d.get("evidence") or ""
    out["tainted_source"] = d.get("tainted_source") or d.get("source") or ""
    out["mitigation_present"] = bool(d.get("mitigation_present", False))
    out["needs_more_context"] = bool(d.get("needs_more_context", False))
    # Sanity: forza verdict valido
    if out["verdict"] not in ("VP-C", "VP-L", "VP-D", "FP"):
        out["verdict"] = "UNKNOWN"
    return out


def _ollama_call(prompt: str, system: str, model: str) -> dict:
    """Chiamata Ollama locale via /api/generate. Output: JSON object normalizzato."""
    full_prompt = (
        f"{system}\n\n"
        f"{prompt}\n\n"
        "Rispondi SOLO con un oggetto JSON valido con le chiavi:\n"
        '  {\n'
        '    "verdict": "VP-C" | "VP-L" | "VP-D" | "FP",\n'
        '    "confidence": 0-100,\n'
        '    "reasoning": "1-3 frasi specifiche al codice",\n'
        '    "key_quote": "riga di codice esatta dal context",\n'
        '    "tainted_source": "origine variabile (es. MCP tool arg, sqlite_master, env var, hardcoded)",\n'
        '    "mitigation_present": true | false,\n'
        '    "needs_more_context": true | false\n'
        '  }\n'
        "Nessun testo prima o dopo il JSON."
    )
    body = json.dumps({
        "model": model,
        "prompt": full_prompt,
        "stream": False,
        "format": "json",   # Ollama: enforce JSON mode
        "options": {"temperature": 0.0, "num_predict": 800},
    }).encode("utf-8")
    req = Request(OLLAMA_API_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    backoff = 1.0
    for attempt in range(3):
        try:
            with urlopen(req, timeout=300) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            text = payload.get("response", "")
            d = _extract_json(text)
            return _normalize_verdict(d)
        except (URLError, TimeoutError, OSError):
            time.sleep(backoff)
            backoff *= 2
        except Exception:
            return {}
    return {}


def _gemini_call(prompt: str, system: str, model: str) -> dict:
    """Google Gemini API (free tier: 1500 req/giorno, 15 req/min)."""
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY non settata")
    url = GEMINI_API_URL_TPL.format(model=model, key=api_key)
    payload = {
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": prompt + "\n\nRispondi SOLO con un oggetto JSON valido."}]}],
        "generationConfig": {"temperature": 0.0, "responseMimeType": "application/json"},
    }
    body = json.dumps(payload).encode("utf-8")
    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    backoff = 2.0
    for attempt in range(5):
        try:
            with urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            d = _extract_json(text)
            return _normalize_verdict(d)
        except HTTPError as e:
            if e.code in (429, 500, 503):
                time.sleep(backoff)
                backoff *= 2
                continue
            return {}
        except (URLError, TimeoutError, OSError):
            time.sleep(backoff)
            backoff *= 2
    return {}


def _groq_call(prompt: str, system: str, model: str) -> dict:
    """Groq API (free tier: 30 req/min, Llama 3.3 70B ultraveloce)."""
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY non settata")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt + "\n\nRispondi SOLO con un oggetto JSON valido."},
        ],
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    req = Request(GROQ_API_URL, data=body, headers=headers, method="POST")
    backoff = 2.0
    for attempt in range(5):
        try:
            with urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            d = _extract_json(text)
            return _normalize_verdict(d)
        except HTTPError as e:
            if e.code in (429, 500, 503):
                time.sleep(backoff)
                backoff *= 2
                continue
            return {}
        except (URLError, TimeoutError, OSError):
            time.sleep(backoff)
            backoff *= 2
    return {}


def _anthropic_call(messages, system, model, max_tokens=1024) -> dict:
    """Chiamata POST cruda a Anthropic Messages API via urllib (stdlib only)."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY non settata nell'environment")
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": messages,
        "tools": [{
            "name": "classify_finding",
            "description": "Emetti la classificazione strutturata del finding analizzato.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "enum": ["VP-C", "VP-L", "VP-D", "FP"],
                        "description": "Classificazione finale del finding."
                    },
                    "confidence": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100,
                        "description": "Confidenza 0-100. <70 indica che servirebbe contesto piu' ampio."
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "1-3 frasi che spiegano il verdetto in modo specifico al codice."
                    },
                    "key_quote": {
                        "type": "string",
                        "description": "La riga di codice esatta che prova il verdetto, copiata dal context."
                    },
                    "tainted_source": {
                        "type": "string",
                        "description": "Source della variabile tainted (es. 'MCP tool arg X', 'sqlite_master query', 'env var', 'hardcoded')."
                    },
                    "mitigation_present": {
                        "type": "boolean",
                        "description": "True se una validazione/escape/allowlist efficace e' visibile nel context."
                    },
                    "needs_more_context": {
                        "type": "boolean",
                        "description": "True se la classificazione richiederebbe analisi di file aggiuntivi (callers, README, altri tool dello stesso server)."
                    }
                },
                "required": ["verdict", "confidence", "reasoning", "key_quote", "tainted_source", "mitigation_present", "needs_more_context"]
            }
        }],
        "tool_choice": {"type": "tool", "name": "classify_finding"},
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_API_VERSION,
        "content-type": "application/json",
    }
    req = Request(ANTHROPIC_API_URL, data=body, headers=headers, method="POST")
    backoff = 1.0
    for attempt in range(5):
        try:
            with urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            if e.code in (429, 529, 500, 502, 503, 504):
                err_body = ""
                try:
                    err_body = e.read().decode("utf-8")[:200]
                except Exception:
                    pass
                time.sleep(backoff)
                backoff *= 2
                continue
            raise
        except (URLError, TimeoutError) as e:
            time.sleep(backoff)
            backoff *= 2
    raise RuntimeError("Anthropic API: failed after retries")


def parse_tool_response(api_response: dict) -> dict:
    """Estrai il JSON del tool_use dalla risposta Anthropic."""
    for block in api_response.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == "classify_finding":
            return dict(block.get("input", {}))
    return {}


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = f"""Sei un analista di sicurezza che classifica finding di scanner MCP (Model Context Protocol).
Devi fornire una classificazione fine-grained basata sul codice sorgente reale del server.

{TAXONOMY}

Regole operative:
- BASA il verdetto SOLO sul codice mostrato. Se non e' sufficiente, marca needs_more_context=true.
- Per VP-C devi vedere prova diretta di tainted source che raggiunge un sink senza validazione.
- Per FP devi identificare un pattern noto (lista nella taxonomy) o evidenza di mitigazione.
- Per VP-L: identifica la causa specifica (hardcoded callers / trusted source / by-design exposure / offensive intentional).
- key_quote DEVE essere una riga di codice presente nel context window.
- confidence riflette quanto sei sicuro: <70 significa che servirebbe leggere altri file."""


def build_user_message(finding: dict, source_context: str, repo_description: str = "", full_file_mode: bool = False) -> str:
    """Compone il messaggio user per il LLM."""
    pieces = [
        f"## Finding categoria: {finding['category']}",
        f"- Server: {finding['server_url']}",
        f"- Repo description: {repo_description or '(N/D)'}",
        f"- File: {finding['file']}:{finding.get('line') or '?'}",
        f"- Pattern detection del framework: {finding['evidence'][:500]}",
    ]
    if finding["code_snippet"]:
        pieces.append(f"- Code snippet originale: `{finding['code_snippet']}`")
    if finding["tool_name"]:
        pieces.append(f"- Tool MCP: `{finding['tool_name']}`")
    if finding["tool_description"]:
        pieces.append(f"- Tool description: {finding['tool_description'][:800]}")
    if finding["framework_reason"]:
        pieces.append(f"- Framework reasoning: {finding['framework_reason'][:500]}")
    pieces.append("")
    pieces.append(f"## Context sorgente {'(FULL FILE)' if full_file_mode else f'(±{MAX_CONTEXT_LINES} righe)'}")
    pieces.append("```")
    pieces.append(source_context[:12000])
    pieces.append("```")
    pieces.append("")
    pieces.append("Classifica il finding via tool `classify_finding`.")
    return "\n".join(pieces)


# ---------------------------------------------------------------------------
# Cache verdetti
# ---------------------------------------------------------------------------

def load_llm_cache() -> dict:
    if LLM_CACHE_FILE.exists():
        try:
            return json.loads(LLM_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_llm_cache(cache: dict):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = LLM_CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(LLM_CACHE_FILE)


def finding_cache_key(finding: dict) -> str:
    """Chiave deterministica per il finding (indipendente da campi mutevoli)."""
    raw = f"{finding['category']}|{finding['server_url']}|{finding['file']}|{finding.get('line','')}|{finding.get('tool_name','')}|{finding['evidence'][:200]}"
    return _safe_filename(raw)


# ---------------------------------------------------------------------------
# Classificazione singolo finding (con eventuale re-prompt)
# ---------------------------------------------------------------------------

def classify_finding(finding: dict, model: str, backend: str, llm_cache: dict) -> dict:
    key = finding_cache_key(finding)
    if key in llm_cache:
        return llm_cache[key]

    # Step 1: fetch sorgente e repo description
    source = github_fetch(finding["server_url"], finding["file"])
    description = github_repo_description(finding["server_url"])
    context = extract_context(source, finding.get("line"))

    # Step 2: prima passata
    user_msg = build_user_message(finding, context, description, full_file_mode=False)
    try:
        verdict = llm_classify(user_msg, SYSTEM_PROMPT, backend, model)
    except Exception as e:
        verdict = {"verdict": "UNKNOWN", "confidence": 0, "reasoning": f"backend error: {e}"}

    # Step 3: se confidence bassa o needs_more_context, re-prompt con full file
    reprompted = False
    if (verdict and (verdict.get("confidence", 0) < LOW_CONFIDENCE_THRESHOLD
                     or verdict.get("needs_more_context"))) and source:
        full_ctx = source[:30000]
        user_msg2 = build_user_message(finding, full_ctx, description, full_file_mode=True)
        user_msg2 += (f"\n\nPrima classificazione (confidence={verdict.get('confidence')}): "
                      f"{verdict.get('verdict')} — {verdict.get('reasoning','')[:200]}.\n"
                      "Rivaluta con il file completo. Se ancora incerto, dai un verdetto best-guess con confidence calibrata.")
        try:
            verdict2 = llm_classify(user_msg2, SYSTEM_PROMPT, backend, model)
            if verdict2 and verdict2.get("confidence", 0) >= verdict.get("confidence", 0):
                verdict = verdict2
                reprompted = True
        except Exception:
            pass

    # Snapshot per riproducibilita'
    out = {
        "finding_key": key,
        "category": finding["category"],
        "server_url": finding["server_url"],
        "file": finding["file"],
        "line": finding.get("line", 0),
        "tool_name": finding.get("tool_name", ""),
        "evidence_excerpt": finding["evidence"][:300],
        "github_file_available": bool(source),
        "verdict": verdict.get("verdict", "UNKNOWN"),
        "confidence": int(verdict.get("confidence", 0)),
        "reasoning": verdict.get("reasoning", ""),
        "key_quote": verdict.get("key_quote", ""),
        "tainted_source": verdict.get("tainted_source", ""),
        "mitigation_present": bool(verdict.get("mitigation_present", False)),
        "needs_more_context": bool(verdict.get("needs_more_context", False)),
        "reprompted": reprompted,
        "model": model,
        "backend": backend,
        "timestamp": int(time.time()),
    }

    llm_cache[key] = out
    return out


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def collect_sample(category_filter=None, limit=None):
    """Raccoglie il sample (default ~1.122 finding) iterando sulle sources per meta-categoria.

    Ogni meta-categoria puo' avere multiple sorgenti vp.json (1+ framework). Ciascuna
    source ha la sua sample_size, e i finding sono concatenati nell'ordine dichiarato.
    """
    out = []
    for cat_key, sources in SAMPLE_SCHEME.items():
        if category_filter and category_filter not in cat_key:
            continue
        for vp_rel, n in sources:
            vp_path = DATA_DIR / vp_rel
            if not vp_path.exists():
                print(f"  [WARN] missing {vp_path}")
                continue
            try:
                data = json.loads(vp_path.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"  [WARN] cannot parse {vp_path}: {e}")
                continue
            findings = data.get("findings", data.get("entries", []))
            if n is not None:
                findings = findings[:n]
            # Estrai il framework name dalla cartella per tracking
            framework = vp_rel.split("/")[0] if "/" in vp_rel else "unknown"
            subcat = vp_rel.split("/")[1] if vp_rel.count("/") >= 1 else ""
            for raw in findings:
                f = normalize_finding(cat_key, raw)
                f["_source_framework"] = framework
                f["_source_subcat"] = subcat
                out.append(f)
            if limit and len(out) >= limit:
                return out[:limit]
    return out


def run_classification(sample, model, backend, concurrency, llm_cache, save_every=10):
    """Processa il sample in parallelo. Salva la cache ogni `save_every` verdetti."""
    results = []
    processed_count = 0
    total = len(sample)
    print(f"  Processo {total} finding (backend={backend}, model={model}, concurrency={concurrency})")
    print(f"  Cache hit attesi: {sum(1 for f in sample if finding_cache_key(f) in llm_cache)}")

    def _do(f):
        return classify_finding(f, model, backend, llm_cache)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(_do, f): f for f in sample}
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as e:
                f = futures[fut]
                r = {
                    "finding_key": finding_cache_key(f),
                    "category": f["category"],
                    "server_url": f["server_url"],
                    "file": f["file"],
                    "line": f.get("line", 0),
                    "verdict": "ERROR",
                    "confidence": 0,
                    "reasoning": f"classification error: {type(e).__name__}: {e}",
                    "model": model,
                    "timestamp": int(time.time()),
                }
            results.append(r)
            processed_count += 1
            if processed_count % save_every == 0:
                save_llm_cache(llm_cache)
                print(f"    [{processed_count}/{total}] cached so far")
    save_llm_cache(llm_cache)
    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

VERDICT_ORDER = ["VP-C", "VP-L", "VP-D", "FP", "UNKNOWN", "ERROR"]


def aggregate_by_category(results):
    cats = {}
    for r in results:
        cat = r["category"]
        cats.setdefault(cat, {v: 0 for v in VERDICT_ORDER})
        cats[cat][r.get("verdict", "UNKNOWN")] = cats[cat].get(r.get("verdict", "UNKNOWN"), 0) + 1
    return cats


def build_report(results) -> str:
    """Genera report Markdown analogo a MANUAL_AUDIT_REPORT.md."""
    cats = aggregate_by_category(results)
    total = len(results)
    grand = {v: 0 for v in VERDICT_ORDER}
    for cstats in cats.values():
        for v, c in cstats.items():
            grand[v] = grand.get(v, 0) + c

    lines = [
        "# Stage 2C — Auto Audit Report",
        "",
        f"Generato il {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "Classificazione automatizzata via Claude API sui medesimi 537 finding del MANUAL_AUDIT_REPORT.md.",
        "Per ogni finding lo script ha (i) fetchato il codice sorgente reale da GitHub, (ii) estratto ±30 righe",
        "di context attorno alla riga del finding, (iii) chiamato Claude API con prompt strutturato e tool_use",
        "per output JSON validato, (iv) re-promptato con file completo se confidence < 70 o needs_more_context.",
        "",
        "## Tabella aggregata per categoria",
        "",
        "| # | Categoria | Sample | VP-C | VP-L | VP-D | FP | Unknown/Err | % VP utili (VP-C+L+D) |",
        "|---|-----------|------:|-----:|-----:|-----:|---:|-----------:|------------------:|",
    ]
    for cat in sorted(cats.keys()):
        s = cats[cat]
        used = s.get("VP-C", 0) + s.get("VP-L", 0) + s.get("VP-D", 0)
        total_cat = sum(s.values())
        pct = 100.0 * used / total_cat if total_cat else 0
        unk = s.get("UNKNOWN", 0) + s.get("ERROR", 0)
        lines.append(f"| {cat.split('.')[0]} | {cat.split('.',1)[1] if '.' in cat else cat} | {total_cat} | {s.get('VP-C',0)} | {s.get('VP-L',0)} | {s.get('VP-D',0)} | {s.get('FP',0)} | {unk} | {pct:.1f}% |")

    lines += [
        "",
        f"**Totale finding analizzati**: {total}",
        "",
        "| Verdetto | Count | % |",
        "|----------|------:|---:|",
    ]
    for v in VERDICT_ORDER:
        c = grand.get(v, 0)
        if c == 0 and v in ("UNKNOWN", "ERROR"):
            continue
        pct = 100.0 * c / total if total else 0
        lines.append(f"| {v} | {c} | {pct:.1f}% |")

    # Sezione per ogni categoria con i singoli finding
    lines += ["", "---", "", "## Dettaglio finding per categoria", ""]
    by_cat = {}
    for r in results:
        by_cat.setdefault(r["category"], []).append(r)
    for cat in sorted(by_cat.keys()):
        lines.append(f"### {cat}")
        lines.append("")
        lines.append("| # | Server | File:Line | Verdict | Conf | Reasoning |")
        lines.append("|---|--------|-----------|:-------:|----:|-----------|")
        for i, r in enumerate(by_cat[cat], 1):
            srv = r["server_url"].replace("https://github.com/", "")
            fileline = f"{r['file']}:{r['line']}" if r.get("line") else r["file"]
            reasoning = (r.get("reasoning", "") or "").replace("|", "\\|")[:200]
            lines.append(f"| {i} | `{srv}` | `{fileline}` | **{r['verdict']}** | {r['confidence']} | {reasoning} |")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Comparison vs MANUAL_AUDIT_REPORT (totali per categoria)
# ---------------------------------------------------------------------------

# Hard-coded dal MANUAL_AUDIT_REPORT.md (Top 100 multi-source, total 1.122 finding)
MANUAL_GROUND_TRUTH = {
    "1.sql-injection":              {"VP-C": 3,  "VP-L": 95, "VP-D": 2,  "FP": 1},
    "2.dangerous-capabilities":     {"VP-C": 0,  "VP-L": 95, "VP-D": 1,  "FP": 2},   # + 2 Ambigui
    "3.credential-leak":            {"VP-C": 68, "VP-L": 7,  "VP-D": 6,  "FP": 14},  # + 5 Ambigui
    "4.ssrf":                       {"VP-C": 3,  "VP-L": 0,  "VP-D": 97, "FP": 0},
    "5.untrusted-content":          {"VP-C": 100,"VP-L": 0,  "VP-D": 0,  "FP": 0},
    "6.path-traversal":             {"VP-C": 59, "VP-L": 36, "VP-D": 4,  "FP": 0},   # +1 Ambiguo
    "7.command-injection":          {"VP-C": 33, "VP-L": 61, "VP-D": 5,  "FP": 1},
    "8.code-injection":             {"VP-C": 64, "VP-L": 30, "VP-D": 6,  "FP": 0},
    "9.input-validation":           {"VP-C": 51, "VP-L": 33, "VP-D": 15, "FP": 1},
    "10.protocol-violation":        {"VP-C": 20, "VP-L": 32, "VP-D": 45, "FP": 2},
    "11.prompt-injection":          {"VP-C": 33, "VP-L": 8,  "VP-D": 1,  "FP": 14},
    "12.insecure-deserialization":  {"VP-C": 2,  "VP-L": 26, "VP-D": 1,  "FP": 2},
    "13.sensitive-file-access":     {"VP-C": 5,  "VP-L": 11, "VP-D": 0,  "FP": 0},
    "14.sensitive-info-disclosure": {"VP-C": 9,  "VP-L": 0,  "VP-D": 0,  "FP": 0},
    "15.access-control":            {"VP-C": 1,  "VP-L": 6,  "VP-D": 0,  "FP": 0},
    "16.data-exfiltration":         {"VP-C": 2,  "VP-L": 0,  "VP-D": 0,  "FP": 0},
    "17.tool-shadowing":            {"VP-C": 1,  "VP-L": 0,  "VP-D": 0,  "FP": 0},
}


def build_comparison(results) -> str:
    """Compara totali auto vs manual per categoria."""
    auto = aggregate_by_category(results)
    lines = [
        "# Comparison Stage 2C (auto) vs MANUAL_AUDIT_REPORT (ground truth)",
        "",
        "Confronto dei conteggi per verdetto, per ogni categoria.",
        "L'agreement rate misura quanto i totali aggregati coincidono.",
        "",
        "| Categoria | Verdetto | Manual | Auto | Δ |",
        "|-----------|----------|------:|----:|--:|",
    ]
    total_diff = 0
    total_manual = 0
    for cat in sorted(MANUAL_GROUND_TRUTH.keys()):
        m = MANUAL_GROUND_TRUTH[cat]
        a = auto.get(cat, {})
        for v in ("VP-C", "VP-L", "VP-D", "FP"):
            mv = m.get(v, 0)
            av = a.get(v, 0)
            d = av - mv
            total_diff += abs(d)
            total_manual += mv
            lines.append(f"| {cat} | {v} | {mv} | {av} | {d:+d} |")

    agreement_pct = 100.0 * (1 - total_diff / max(total_manual, 1))
    lines += [
        "",
        f"**Total absolute difference**: {total_diff} (su {total_manual} verdetti manuali)",
        f"**Aggregate agreement**: {agreement_pct:.1f}%",
        "",
        "*Nota*: questa metrica confronta i conteggi aggregati. Per agreement per-finding",
        "serve allineare ogni verdetto auto al corrispondente verdetto manuale (campo `finding_key`).",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Stage 2C auto-audit di VP/FP")
    ap.add_argument("--all", action="store_true", help="Processa tutti i 1.122 finding")
    ap.add_argument("--category", default=None, help="Filtra una sola categoria (es. 'sql-injection')")
    ap.add_argument("--limit", type=int, default=None, help="Massimo N finding totali (per test)")
    ap.add_argument("--backend", default=DEFAULT_BACKEND,
                    choices=["ollama", "anthropic", "gemini", "groq"],
                    help=f"Backend LLM (default {DEFAULT_BACKEND}). Ollama e' locale e gratuito.")
    ap.add_argument("--model", default=None, help="Modello (default dipende dal backend)")
    ap.add_argument("--concurrency", type=int, default=5, help="Worker paralleli (default 5)")
    ap.add_argument("--report-only", action="store_true", help="Rigenera solo i report dalla cache esistente")
    ap.add_argument("--dry-run", action="store_true", help="Stampa il sample senza chiamare API")
    args = ap.parse_args()

    # Default model per backend
    if args.model is None:
        args.model = {
            "anthropic": DEFAULT_MODEL_CLAUDE,
            "ollama": DEFAULT_MODEL_OLLAMA,
            "gemini": DEFAULT_MODEL_GEMINI,
            "groq": DEFAULT_MODEL_GROQ,
        }[args.backend]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if not args.all and not args.category and not args.report_only:
        print("Specifica --all o --category XXX (o --report-only). --help per opzioni.")
        sys.exit(1)

    print("=" * 70)
    print("Stage 2C — Auto Audit")
    print("=" * 70)

    sample = collect_sample(args.category, args.limit)
    print(f"Sample raccolto: {len(sample)} finding")

    if args.dry_run:
        for f in sample[:20]:
            print(f"  [{f['category']}] {f['server_url']} {f['file']}:{f.get('line','')}")
        return

    llm_cache = load_llm_cache()
    print(f"Cache verdetti gia' presenti: {len(llm_cache)}")

    if args.report_only:
        # Usa solo i verdetti dalla cache che matchano il sample
        results = []
        for f in sample:
            k = finding_cache_key(f)
            if k in llm_cache:
                results.append(llm_cache[k])
            else:
                results.append({
                    "finding_key": k,
                    "category": f["category"],
                    "server_url": f["server_url"],
                    "file": f["file"],
                    "line": f.get("line", 0),
                    "verdict": "UNKNOWN",
                    "confidence": 0,
                    "reasoning": "non in cache (esegui senza --report-only)",
                })
    else:
        # Check pre-volo per ogni backend
        if args.backend == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERRORE: ANTHROPIC_API_KEY non settata.")
            sys.exit(2)
        if args.backend == "gemini" and not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
            print("ERRORE: GEMINI_API_KEY non settata. Ottieni una key gratis su aistudio.google.com")
            sys.exit(2)
        if args.backend == "groq" and not os.environ.get("GROQ_API_KEY"):
            print("ERRORE: GROQ_API_KEY non settata. Ottieni una key gratis su console.groq.com")
            sys.exit(2)
        if args.backend == "ollama":
            # Test che Ollama risponda
            try:
                with urlopen("http://localhost:11434/api/tags", timeout=5) as r:
                    models = [m["name"] for m in json.loads(r.read()).get("models", [])]
                if args.model not in models:
                    print(f"AVVISO: modello '{args.model}' non trovato in Ollama. Modelli disponibili: {models[:5]}")
                    print(f"Lancia: ollama pull {args.model}")
                    sys.exit(2)
            except Exception as e:
                print(f"ERRORE: Ollama non raggiungibile su localhost:11434 ({e}). Lancia: ollama serve")
                sys.exit(2)
        results = run_classification(sample, args.model, args.backend, args.concurrency, llm_cache)

    # Save verdicts.json
    verdicts_path = OUTPUT_DIR / "verdicts.json"
    verdicts_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  -> {verdicts_path}")

    # Save report.md
    report = build_report(results)
    report_path = OUTPUT_DIR / "auto_audit_report.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"  -> {report_path}")

    # Save comparison.md
    if args.all or not args.category:
        comp = build_comparison(results)
        comp_path = OUTPUT_DIR / "comparison_vs_manual.md"
        comp_path.write_text(comp, encoding="utf-8")
        print(f"  -> {comp_path}")

    # Stampa rapido riassunto
    by_v = {}
    for r in results:
        by_v[r["verdict"]] = by_v.get(r["verdict"], 0) + 1
    print()
    print("Riassunto verdetti:")
    for v in VERDICT_ORDER:
        if v in by_v:
            print(f"  {v}: {by_v[v]}")


if __name__ == "__main__":
    main()
