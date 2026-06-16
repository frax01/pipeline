from pathlib import Path
import re
import sys
import platform
import shutil

BASE_DIR = Path.home() / "Desktop/Pipeline"
CONFIG = BASE_DIR / "claude_desktop_config.json"
FRAMEWORKS = BASE_DIR / "analysis" / "frameworks.json"
RECAP_SERVER = BASE_DIR / "analysis" / "recap_server.json"

FRAMEWORKS_ROOT = Path.home() / "Desktop/Frameworks"

# Directory dei framework effettivi (per eseguire i comandi npm/bin)
MCP_GUARD_DIR = FRAMEWORKS_ROOT / "mcp-guard"
MCP_WATCH_DIR = FRAMEWORKS_ROOT / "mcp-watch"
MCP_CHECK_DIR = FRAMEWORKS_ROOT / "mcp-check"

# Directory dei tool (per i risultati e log)
def _get_tool_dir(name):
    d = BASE_DIR / f"mcp_{name}"
    if d.exists(): return d
    return BASE_DIR / f"tool_mcp_{name}"

MCP_SCAN_DIR = _get_tool_dir("scan")
MCP_SHIELD_DIR = _get_tool_dir("shield")
MCP_SECURITY_SCAN_DIR = _get_tool_dir("security_scan")

FRAMEWORK_PATHS = {
    "mcp-guard": BASE_DIR / "analysis" / "mcp-guard.json",
    "mcp-watch": BASE_DIR / "analysis" / "mcp-watch.json",
    "fuzzing": BASE_DIR / "analysis" / "fuzzing.json",
    "mcp-scan": BASE_DIR / "analysis" / "mcp-scan.json",
    "mcp-shield": BASE_DIR / "analysis" / "mcp-shield.json",
    "mcp-security-scan": BASE_DIR / "analysis" / "mcp-security-scan.json",
    "mcp-check": BASE_DIR / "analysis" / "mcp-check.json",
}

NPM = shutil.which("npm") or r"C:\Program Files\nodejs\npm.cmd"
NPX = shutil.which("npx") or str(Path.home() / "AppData/Roaming/npm/npx.cmd")
PNPM = shutil.which("pnpm") or "pnpm"

_uvx_path = shutil.which("uvx")
if not _uvx_path and platform.system() != "Windows":
    _local_uvx = Path.home() / ".local/bin/uvx"
    if _local_uvx.exists():
        _uvx_path = str(_local_uvx)
UVX = _uvx_path or str(Path.home() / "AppData/Local/Programs/Python/Python313/Scripts/uvx.exe")

# Dataset unico GitHub+NPX (69.104 server). Colonne: Link, Type (github|npx).
# Costruito da fuzzing/postprocessing/special/build_unified_excel.py. E' l'UNICO file di input
# della pipeline: tutti i tool leggono da qui.
EXCEL_PATH = Path.home() / "Desktop" / "Pipeline" / "0.0. All servers unified (69104).xlsx"
# Alias mantenuti per retrocompatibilita': ora puntano tutti al dataset unico.
EXCEL_PATH_NPX = EXCEL_PATH
EXCEL_PATH_UNIFIED = EXCEL_PATH
TIMEOUT_SECONDS = 3600

MCP_SECURITY_SCAN_CATEGORIES = {
    "BASE-01": "initialization-error",
    "X-01": "dangerous-capabilities",
    "P-02": "prompt-injection",
    "X-03": "rug-pull",
    "R-01": "path-traversal",
    "R-02": "sensitive-file-access",
    "R-03": "sensitive-resource-exposure",
    "X-02": "input-validation",
    "A-03": "data-leak",
    "P-03": "indirect-prompt-injection",
    "RC-01": "remote-access-control"
}

ANSI_ESCAPE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)

TS_SCRIPT = BASE_DIR / "frameworks" / "listTools.ts"
RECAP_PATH = Path.cwd() / "recap"

# Comandi per l'esecuzione dei framework
cmd_shield = [NPX, "mcp-shield", "--path", str(CONFIG)]
cmd_scan = [UVX, "mcp-scan", str(CONFIG)]
cmd_guard = [sys.executable, str(MCP_GUARD_DIR / "mcp_scanner.py")]
cmd_security_scan = [UVX, "mcp-security-scan", str(CONFIG)]

ISSUE_CODE_MAP = {
    "E001": "prompt-injection",
    # ... (altri codici)
}

# Mappa codici TFxxx (toxic flow) -> nome categoria. Fallback "unknown-toxic-flow"
# se il codice non e' in mappa. Vuoto = tutti i TF saranno "unknown-toxic-flow".
TOXIC_FLOW_MAP = {
    "TF001": "exfiltrate-conversation",
    "TF002": "external-input-privileged-write",
}

# Codici issue da ignorare (es. info/internal noise dello scanner).
# Vuoto = nessun codice viene saltato.
SKIP_ISSUE_CODES = set()
