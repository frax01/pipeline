"""
Modulo per gestire i file JSON di recap per framework.
Ogni framework ha un file JSON nella cartella recap con formato:
{
    "url1": "language status",
    "url2": "language status",
    ...
}
"""
import json
from pathlib import Path
from .config import RECAP_PATH


def get_recap_file_path(framework_name: str) -> Path:
    """Restituisce il path del file recap per un framework specifico."""
    return RECAP_PATH / f"{framework_name}.json"


def load_recap_framework(framework_name: str) -> dict:
    """Carica il file recap di un framework. Restituisce dict vuoto se non esiste."""
    file_path = get_recap_file_path(framework_name)
    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def save_recap_framework(framework_name: str, data: dict) -> None:
    """Salva il file recap di un framework."""
    file_path = get_recap_file_path(framework_name)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def update_recap_framework(
    framework_name: str,
    server_url: str,
    language: str,
    status: str
) -> None:
    """
    Aggiorna il recap di un framework con i dati di un server analizzato.
    
    Args:
        framework_name: Nome del framework (es. "mcp-guard", "mcp-watch")
        server_url: URL del server analizzato
        language: Linguaggio del server (es. "python", "nodejs")
        status: Stato dell'analisi (es. "completed", "failed")
    """
    recap = load_recap_framework(framework_name)
    recap[server_url] = f"{language} {status}"
    save_recap_framework(framework_name, recap)


def reset_all_recap_frameworks() -> None:
    """Resetta tutti i file recap dei framework nella cartella recap."""
    framework_names = [
        "mcp-guard",
        "mcp-watch",
        "fuzzing",
        "mcp-scan",
        "mcp-shield",
        "mcp-security-scan",
        "mcp-check",
        "llm-analysis",
        "llm-proxy"
    ]
    for name in framework_names:
        save_recap_framework(name, {})
