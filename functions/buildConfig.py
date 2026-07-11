import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from .config import CONFIG, NPM
import json
import platform

def ensure_bun_installed():
    if shutil.which("bun"):
        print("Bun già installato")
        return shutil.which("bun")

    print("Bun non trovato, installazione in corso...")

    system = platform.system()

    if system == "Windows":
        install_cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "irm https://bun.sh/install.ps1 | iex"
        ]
        bun_path = os.path.expanduser("~/.bun/bin/bun.exe")
    elif system in ("Darwin", "Linux"):
        install_cmd = [
            "bash",
            "-c",
            "curl -fsSL https://bun.sh/install | bash"
        ]
        bun_path = os.path.expanduser("~/.bun/bin/bun")
    else:
        raise RuntimeError(f"Sistema operativo non supportato: {system}")

    subprocess.run(install_cmd, check=True, timeout=120)

    if not os.path.exists(bun_path):
        raise RuntimeError("Installazione Bun fallita")

    print("Bun installato in:", bun_path)
    print("Riavvia il kernel Jupyter per usarlo come 'bun'")

    return bun_path

def is_bun_project(data: dict, repo_path: Path) -> bool:
    scripts = data.get("scripts", {})
    build_cmd = scripts.get("build", "")

    if "bun" in build_cmd:
        return True

    if (repo_path / "bun.lockb").exists():
        return True

    dev_deps = data.get("devDependencies", {})
    if "@types/bun" in dev_deps:
        return True

    return False

def write_mcp_config(server_name: str, command: str, args: list[str], cwd: Path):
    config_mcp = CONFIG
    # Resolve relative file paths in args to absolute paths,
    # because mcp-shield does not respect the "cwd" field.
    resolved_args = []
    for arg in args:
        candidate = cwd / arg
        if candidate.exists():
            resolved_args.append(str(candidate))
        else:
            resolved_args.append(arg)
    config = {
        "mcpServers": {
            server_name: {
                "command": command,
                "args": resolved_args,
            }
        }
    }
    config_mcp.write_text(json.dumps(config, indent=2))

def detect_python_runner(repo_path: Path):
    """
    Returns (runner, name, script_name).
    runner in {"uv", "python"} — "uvx" is NO LONGER returned, because
    `uvx <name>@latest` pulls from PyPI and ignores the local cloned code
    (see ANALYSIS_REPORT §5). We always prefer running the local repo.
    script_name: first entry from [project.scripts] (used only as a last-
    resort fallback via `uv run <script_name>` when no local entry point
    file is found — `uv run` still runs the LOCAL project, not PyPI).
    """
    pyproject = repo_path / "pyproject.toml"
    uv_lock = repo_path / "uv.lock"

    name = None
    script_name = None

    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8", errors="ignore")

        match = re.search(r'^name\s*=\s*"([^"]+)"', content, re.MULTILINE)
        if match:
            name = match.group(1)

        if "[project.scripts]" in content:
            scripts_block = re.search(
                r'\[project\.scripts\](.*?)(?:\n\[|\Z)',
                content,
                re.DOTALL,
            )
            if scripts_block:
                first_script = re.search(
                    r'^\s*"?([a-zA-Z0-9_\-\.]+)"?\s*=',
                    scripts_block.group(1),
                    re.MULTILINE,
                )
                if first_script:
                    script_name = first_script.group(1)

        if "tool.uv" in content or uv_lock.exists() or "[project.scripts]" in content:
            return ("uv", name, script_name)

    return ("python", name, script_name)

def prepare_go_repo(repo_path: Path) -> dict:
    result = {
        "strategy": None,
        "error": None,
        "command": None,
        "main": None,
        "cwd": None
    }

    # 1. SETUP PATH ASSOLUTI
    repo_path = repo_path.resolve()
    
    go_mod_files = list(repo_path.rglob("go.mod"))
    if not go_mod_files:
        result["strategy"] = "not_go"
        return result
    
    go_mod_files.sort(key=lambda p: len(p.parts))
    project_root = go_mod_files[0].parent.resolve()
    result["cwd"] = project_root 

    go_bin = shutil.which("go")
    if go_bin is None:
        result["strategy"] = "go_missing"
        result["error"] = "go_not_installed"
        return result

    # 2. SCARICA DIPENDENZE
    #print(f"Downloading dependencies in {project_root}...")
    subprocess.run([go_bin, "mod", "download"], cwd=project_root, check=False, capture_output=True, timeout=90)

    # 3. TROVA IL MAIN (Scoring System)
    candidates = []
    ignore_dirs = {"example", "examples", "test", "tests", "client", "cli", "demo", "vendor"}
    mcp_indicators = ["github.com/mark3labs/mcp-go", "github.com/modelcontextprotocol", "server"]

    for go_file in project_root.rglob("*.go"):
        parts = set(p.lower() for p in go_file.parts)
        if not parts.isdisjoint(ignore_dirs): continue

        try:
            content = go_file.read_text(encoding="utf-8", errors="ignore")
            if not (re.search(r'^package\s+main\b', content, re.MULTILINE) and 
                    re.search(r'^func\s+main\s*\(\s*\)', content, re.MULTILINE)):
                continue

            score = 0
            path_str = str(go_file).lower()
            if "cmd" in parts: score += 10
            if "server" in path_str: score += 20
            if "mcp" in path_str: score += 15
            for indicator in mcp_indicators:
                if indicator in content: score += 50

            candidates.append({"path": go_file, "score": score})
        except Exception: continue

    if not candidates:
        result["strategy"] = "no_main_found"
        return result

    candidates.sort(key=lambda x: x["score"], reverse=True)
    selected_main = candidates[0]["path"]
    
    # 4. COMPILAZIONE (Build Strategy con CGO DISABILITATO)
    main_dir = selected_main.parent
    exe_name = "mcp-server.exe" if platform.system() == "Windows" else "mcp-server"
    output_exe = main_dir / exe_name
    
    #print(f"Building binary from {main_dir}...")
    
    # --- MODIFICA QUI: Creiamo un ambiente personalizzato ---
    build_env = os.environ.copy()
    build_env["CGO_ENABLED"] = "0"  # <--- DISABILITA L'USO DI GCC/C
    # --------------------------------------------------------

    build_cmd = [go_bin, "build", "-o", exe_name, "."]
    
    build_proc = subprocess.run(
        build_cmd,
        cwd=main_dir,
        env=build_env, # <--- Passiamo l'ambiente modificato
        capture_output=True,
        text=True,
        timeout=90
    )
    
    if build_proc.returncode != 0:
        print(f"Build Failed:\n{build_proc.stderr}")
        result["error"] = "build_failed"
        return result

    #print(f"Build Success: {output_exe}")

    # 5. CONFIGURAZIONE FINALE
    result["strategy"] = "go_build"
    result["command"] = str(output_exe)
    result["main"] = ["go_main"]
    result["cwd"] = project_root
    
    return result

def prepare_node_repo(repo_path: Path, language: str) -> dict:
    npm_cmd = NPM
    from functions.config import PNPM

    result = {
        "strategy": None,
        "error": None,
        "main": None,
        "command": None
    }

    if language == 'nodejs':
        pkg = repo_path / "package.json"
        if not pkg.exists():
            result["strategy"] = "not_node"
            result["main"] = ["not_runnable"]
            return result

        data = json.loads(pkg.read_text())
        scripts = data.get("scripts", {})
        bin_field = data.get("bin")
        main_field = data.get("main")
        has_start = "start" in scripts
        result["command"] = "node"

        has_bin = bin_field is not None
        has_build = "build" in scripts
        has_dist = (repo_path / "dist").exists()
        has_tsconfig = (repo_path / "tsconfig.json").exists()

        is_bun = is_bun_project(data, repo_path)
        if is_bun:
            try:
                BUN_PATH = ensure_bun_installed()
                run_cmd([BUN_PATH, "install"], repo_path)
            except Exception as e:
                print(f"Bun install failed ({e}), falling back to npm")
                is_bun = False
                if not (repo_path / "node_modules").exists():
                    if platform.system() in ("Darwin", "Linux"):
                        npm_cmd = "npm"
                    run_cmd([npm_cmd, "install"], repo_path)
        else:
            if not (repo_path / "node_modules").exists():
                if (repo_path / "pnpm-lock.yaml").exists():
                    npm_cmd = PNPM
                elif platform.system() in ("Darwin", "Linux"):
                    npm_cmd = "npm"
                run_cmd([npm_cmd, "install"], repo_path)
        if has_build and not has_dist:
            if is_bun:
                try:
                    BUN_PATH = ensure_bun_installed()
                    code, _ = run_cmd([BUN_PATH, "run", "build"], repo_path)
                except Exception as e:
                    print(f"Bun build failed ({e}), falling back to npm build")
                    code = run_build_cmd(repo_path)
                result["strategy"] = "bun_build"
            else:
                code = run_build_cmd(repo_path)
                result["strategy"] = "npm_build"
        elif has_dist:
           result["strategy"] = "prebuilt"
        else:
            result["strategy"] = "no_build_needed"

        if has_start and len(scripts.get("start").split(" "))<3: #TO CHECK
            start_cmd = scripts.get("start")
            parts = shlex.split(start_cmd)
            if len(parts) == 1:
                command = "node"
                args = parts[0:]
            else:
                command = parts[0]
                args = parts[1:]
            result["main"] = args
        elif main_field is not None:
            result["main"] = [main_field]
        elif data.get("module") is not None:
            result["main"] = [data.get("module")]
        else:
            candidates = [
                ["node", "dist/index.js"],
                ["node", "build/index.js"],
                ["node", "src/index.js"],
                ["node", "dist/mcp.js"],
                ["node", "index.js"],
                ["node", "dist/index.ts"],
                ["node", "build/index.ts"],
                ["node", "src/index.ts"],
                ["node", "index.ts"],
            ]
            for cmd, args in candidates:
                target = repo_path / args
                if target.exists():
                    # If it's a .ts file and we have bun, use bun even if candidate said node
                    if args.endswith(".ts") and is_bun:
                        try:
                            command = ensure_bun_installed()
                        except:
                            command = cmd
                    else:
                        command = cmd
                    
                    result["command"] = command
                    result["main"] = [args]
                    print("Found candidate:", command, args)
                    break
                else:
                    result["main"] = ["not_runnable"]
        return result
    elif language.lower() == 'python':

        runner, name, script_name = detect_python_runner(repo_path)

        # Always prefer running the LOCAL cloned code. Look for a known
        # entry-point file first; only fall back to `uv run <script_name>`
        # (which still executes the local project) if no file is found.
        candidates = [
            "server.py",
            "main.py",
            "app.py",
            "__main__.py",
            "src/server.py",
            "src/main.py",
            "src/app.py",
            "app/main.py",
            "server/main.py",
        ]

        for entry in candidates:
            target = repo_path / entry
            if target.exists():
                if runner == "uv":
                    result["command"] = "uv"
                    result["main"] = ["run", "python", entry]
                else:
                    result["command"] = "python"
                    result["main"] = [entry]
                return result

        # Last resort: package defines [project.scripts] but no obvious local
        # entry-point file. Use `uv run <script_name>` which installs the
        # project from the LOCAL pyproject.toml (NOT from PyPI) and runs the
        # declared script. This avoids the uvx-pulls-from-PyPI bug while
        # still giving coverage on packages that rely on entry points.
        if runner == "uv" and script_name:
            result["command"] = "uv"
            result["main"] = ["run", script_name]
            return result

    result["command"] = "go"
    result["main"] = ["not_runnable"]
    result["strategy"] = "not_runnable"
    return result

def run_build_cmd(repo_path: Path) -> int:
    system = platform.system()

    if system == "Windows":
        script_path = str(Path(__file__).resolve().parent.parent / "npm_runner" / "npm_build.ps1")
        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", script_path,
            str(repo_path)
        ]
    elif system in ("Darwin", "Linux"):
        script_path = str(Path(__file__).resolve().parent.parent / "npm_runner" / "npm_build.sh")
        cmd = [
            "bash",
            script_path,
            str(repo_path)
        ]
    else:
        raise RuntimeError(f"Unsupported OS: {system}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180
    )

    if result.returncode != 0:
        print(f"Build Failed (code {result.returncode}):\n{result.stderr}")

    return result.returncode

def run_cmd(cmd: list[str], cwd: Path, capture: bool = False) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=180
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    if not capture and output:
        print(output)
    return proc.returncode, output

def clone_repo(repo_url: str, repo_base: Path):
    repo_name = repo_url.rstrip("/").split("/")[-1]
    repo_path = repo_base / repo_name

    if repo_path.exists():
        return repo_path

    proc = subprocess.run(
        ["git", "clone", "--depth=1", repo_url, str(repo_path)],
        capture_output=True,
        text=True,
        timeout=60
    )
    if proc.returncode != 0:
        print(f"Git Clone Failed:\n{proc.stderr}")
        return None
    return repo_path

def npm_pack_source(package_name: str, repo_base: Path):
    """Come clone_repo ma per un pacchetto NPX/npm: `npm pack` scarica il tarball
    PUBBLICATO del pacchetto, lo estrae e ritorna la cartella del sorgente (per
    l'analisi statica dei tool source-based, es. mcp-guard). None se fallisce."""
    import tempfile
    import tarfile
    name = (package_name or "").strip()
    if not name:
        return None
    dest = Path(repo_base) / (re.sub(r'[^A-Za-z0-9._-]', '_', name) + "__npx")
    if dest.exists():
        return dest
    npm_cmd = "npm" if platform.system() in ("Darwin", "Linux") else NPM
    tmp = tempfile.mkdtemp(prefix="npmpack_", dir=str(repo_base))
    try:
        proc = subprocess.run([npm_cmd, "pack", name], cwd=tmp,
                              capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            print(f"npm pack failed for {name}: {(proc.stderr or '')[:200]}")
            return None
        tgz = [f for f in os.listdir(tmp) if f.endswith(".tgz")]
        if not tgz:
            return None
        with tarfile.open(os.path.join(tmp, tgz[0]), "r:gz") as tar:
            if hasattr(tarfile, "data_filter"):
                tar.extractall(path=tmp, filter="data")
            else:
                tar.extractall(path=tmp)
        extracted = os.path.join(tmp, "package")
        src = extracted if os.path.isdir(extracted) else tmp
        shutil.move(src, str(dest))
        return dest
    except Exception as e:
        print(f"npm pack error {name}: {e}")
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def build_mcp_config(repo_path: Path, language: str):
    server_name = repo_path.name
    
    if language == 'go':
        prep = prepare_go_repo(repo_path)
    else:
        prep = prepare_node_repo(repo_path, language) 

    if prep.get("error") or prep.get("strategy") in ["not_go", "not_runnable", "no_main_found"]:
        print(f"Skipping {server_name}: {prep.get('error') or prep.get('strategy')}")
        # Clear the config file to avoid stale data if mcp-shield is still called
        CONFIG.write_text(json.dumps({"mcpServers": {}}, indent=2))
        return server_name, None, None

    actual_cwd = prep.get("cwd") if prep.get("cwd") else repo_path

    write_mcp_config(
        server_name = server_name,
        command = prep["command"],
        args = prep["main"],
        cwd = actual_cwd
    )

    return server_name, prep["command"], prep["main"]