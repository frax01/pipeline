
import subprocess
import json
import os
from functions.config import BASE_DIR

from pathlib import Path as _Path
SCANORAMA_PATH = str(_Path.home() / "Desktop" / "Frameworks" / "scanorama")

def execute_scanorama(repo_path):
    """
    Esegue Scanorama sul repository specificato.
    Restituisce il report JSON parsed e lo status.
    """
    
    # Costruisci il comando
    # node dist/index.js --path "{repo_path}" --provider ollama --model qwen3-coder:480b-cloud --output report.json
    
    output_file = "report.json"
    
    cmd = [
        "node",
        "dist/index.js",
        "--path", str(repo_path),
        "--provider", "ollama",
        "--model", "qwen2.5-coder:7b",
        "--output", output_file,
        "-y"
    ]
    
    try:        
        # Uso subprocess.run senza catturare l'output ma silenziandolo (DEVNULL)
        # Questo evita deadlock e nasconde l'output come richiesto
        subprocess.run(
            cmd,
            cwd=SCANORAMA_PATH,
            check=False,
            timeout=600  # 10 minuti di timeout
        )
            
        report_path = os.path.join(SCANORAMA_PATH, output_file)
        
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                    return {"scanorama": data, "status": "completed"}
                except json.JSONDecodeError:
                    print("Errore nel parsing del report JSON di Scanorama.")
                    return {"scanorama": {}, "status": "failed"}
        else:
            print("File report.json non trovato.")
            return {"scanorama": {}, "status": "failed"}
            
    except subprocess.TimeoutExpired:
        print("Scanorama timeout after 600s")
        return {"scanorama": {}, "status": "timeout"}
    except Exception as e:
        print(f"Eccezione durante l'esecuzione di Scanorama: {e}")
        return {"scanorama": {}, "status": "failed"}
