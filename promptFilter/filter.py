import json
import os

# 1. DEFINIZIONE DELLE KEYWORD PER MCP
# Queste parole chiave servono a filtrare solo i prompt che hanno senso 
# per un attacco a un tool (es. accesso ai file, esecuzione codice).

# Ottieni il percorso assoluto della directory in cui si trova questo script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MCP_KEYWORDS = [
    "script", "code", "python", "bash", "shell", "terminal", 
    "delete", "remove", "files", "directory", "system", "exec", 
    "hack", "exploit", "bypass", "login", "password", "credential",
    "download", "upload", "network", "scan", "root", "admin"
]

def contains_keyword(text):
    """Controlla se il testo contiene almeno una keyword tecnica."""
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in MCP_KEYWORDS)

def load_text_payloads(filenames):
    """Carica i file .txt (una frase per riga) e filtra."""
    valid_payloads = []
    for filename in filenames:
        if not os.path.exists(filename):
            print(f"⚠️ File non trovato: {filename}")
            continue
            
        print(f"📂 Processando {filename}...")
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            for line in lines:
                clean_line = line.strip()
                if len(clean_line) > 10 and contains_keyword(clean_line):
                    valid_payloads.append(clean_line)
    return valid_payloads

def load_jailbreaks(filenames):
    """Carica i jailbreak complessi dai JSON."""
    templates = []
    
    for filename in filenames:
        if os.path.exists(filename):
            print(f"📂 Caricando {os.path.basename(filename)}...")
            with open(filename, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    
                    # 1. Gestione AutoDAN (Lista di stringhe) o file simili
                    if isinstance(data, list):
                        # Se è una lista di stringhe (es. AutoDAN)
                        if all(isinstance(item, str) for item in data):
                            templates.extend(data)
                        # Se è una lista di oggetti o stringhe miste
                        elif len(data) > 0:
                            # Prendi il primo elemento se è DAN/ChatGPT Dev Mode
                            if "DAN_Jailbreak" in filename or "ChatGPT" in filename:
                                templates.append(data[0])
                            else:
                                # Fallback generico
                                templates.extend([str(item) for item in data])
                except json.JSONDecodeError:
                    print(f"⚠️ Errore lettura JSON: {filename}")
        else:
             print(f"⚠️ File template non trovato: {filename}")
                
    return templates

def main():
    # File di input (quelli che hai caricato)
    payload_files = [
        os.path.join(BASE_DIR, "malicious_uses.txt"),
        os.path.join(BASE_DIR, "harmbench_prompts.txt")
    ]
    jailbreak_files = [
        os.path.join(BASE_DIR, "autodan_prompts.json"),
        os.path.join(BASE_DIR, "DAN_Jailbreak.json"),
        os.path.join(BASE_DIR, "ChatGPT_Developer_Mode_v2.json")
    ]

    print("--- INIZIO FILTRAGGIO PER MCP ---")

    # 1. Estrazione Payloads (Intenti Tecnici)
    tech_payloads = load_text_payloads(payload_files)
    print(f"✅ Trovati {len(tech_payloads)} payload rilevanti per MCP (filtrati per keyword).")

    # 2. Estrazione Jailbreaks (Template)
    jailbreaks = load_jailbreaks(jailbreak_files)
    print(f"✅ Trovati {len(jailbreaks)} template di Jailbreak.")

    # 3. Salvataggio Output
    output_payloads = os.path.join(BASE_DIR, "mcp_filtered_payloads.json")
    output_templates = os.path.join(BASE_DIR, "mcp_jailbreak_templates.json")

    with open(output_payloads, 'w') as f:
        json.dump(tech_payloads, f, indent=4)
    
    with open(output_templates, 'w') as f:
        json.dump(jailbreaks, f, indent=4)

    print("\n--- RISULTATO ---")
    print(f"💾 Salvato: {output_payloads} (Usa questi come argomenti o obiettivi)")
    print(f"💾 Salvato: {output_templates} (Usa questi come prefissi per sbloccare l'LLM)")

if __name__ == "__main__":
    main()

# mcp_filtered_payloads.json (Il Payload Tecnico):
# Contiene le azioni o i comandi specifici che l'attaccante vuole eseguire tramite i tool (es. "entra nella cartella X", "esegui print('ciao')", ecc.).
# Sono stati filtrati cercando keyword tecniche come exec, shell, root, hack in malicious_uses.txt e harmbench_prompts.txt.

# mcp_jailbreak_templates.json (Il Template di Jailbreak):
# Contiene le tecniche di persuasione (come DAN, AutoDAN, Developer Mode) per aggirare i filtri etici dell'LLM.
# Questi da soli spesso non fanno nulla di tecnico, ma servono a "sbloccare" l'LLM affinché accetti i comandi del primo file.

# fonti:
# https://github.com/NVIDIA/garak/blob/main/garak/data/harmbench/harmbench_prompts.txt
# https://github.com/NVIDIA/garak/blob/main/garak/data/donotanswer/malicious_uses.txt
# https://github.com/NVIDIA/garak/blob/main/garak/data/dan/DAN_Jailbreak.json
# https://github.com/NVIDIA/garak/blob/main/garak/data/dan/ChatGPT_Developer_Mode_v2.json
# https://github.com/NVIDIA/garak/blob/main/garak/data/autodan/autodan_prompts.json