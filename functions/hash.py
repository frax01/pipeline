import hashlib
from pathlib import Path

# Directory da ignorare
IGNORE_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "__pycache__",
    ".venv"
}

# File da ignorare
IGNORE_FILES = {
    ".DS_Store"
}

def compute_server_hash(
    root: Path,
    algo: str = "sha256"
) -> str:
    """
    Calcola un hash deterministico del contenuto di un server MCP.
    L'hash NON dipende dal nome della cartella root.
    """
    hasher = hashlib.new(algo)

    files = []

    for path in root.rglob("*"):
        if path.is_dir():
            if path.name in IGNORE_DIRS:
                continue
        else:
            if path.name in IGNORE_FILES:
                continue
            if any(part in IGNORE_DIRS for part in path.parts):
                continue

            rel_path = path.relative_to(root).as_posix()
            files.append((rel_path, path))

    # Ordine deterministico
    files.sort(key=lambda x: x[0])

    for rel_path, file_path in files:
        hasher.update(rel_path.encode("utf-8"))
        hasher.update(b"\0")
        try:
            content = file_path.read_bytes()
        except Exception:
            continue
        hasher.update(content)
        hasher.update(b"\0")

    return hasher.hexdigest()
