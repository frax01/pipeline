import requests
import json
import time
import os
from datetime import datetime, timedelta
# trovati 6704 server
# --- CONFIGURAZIONE ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")  # NECESSARIO per volumi alti
OUTPUT_FILE = "16_github_search.json"
# Data di inizio approssimativa dell'ecosistema MCP (Novembre 2024)
START_DATE = datetime(2024, 10, 1) 
DAYS_PER_SLICE = 10  # Finestre di 10 giorni per stare sotto i 1000 risultati per fetta

def get_servers_by_time_slice():
    base_url = "https://api.github.com/search/repositories"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {GITHUB_TOKEN}"
    }

    all_servers = {} # Uso un dizionario per evitare duplicati automatici (chiave = URL)
    
    current_date = START_DATE
    end_date = datetime.now()

    print(f"Inizio scansione temporale dal {current_date.strftime('%Y-%m-%d')} ad oggi...")

    while current_date < end_date:
        # Calcola la finestra temporale
        next_date = current_date + timedelta(days=DAYS_PER_SLICE)
        if next_date > end_date:
            next_date = end_date
        
        # Formatta le date per la query di GitHub (YYYY-MM-DD)
        date_query = f"created:{current_date.strftime('%Y-%m-%d')}..{next_date.strftime('%Y-%m-%d')}"
        query = f"topic:mcp-server {date_query}"
        
        print(f"\nScansione periodo: {date_query}")
        
        page = 1
        while True:
            params = {
                "q": query,
                "per_page": 100,
                "page": page
            }

            try:
                response = requests.get(base_url, headers=headers, params=params)
                
                # Gestione Rate Limit
                if response.status_code == 403 or response.status_code == 429:
                    print("Rate limit raggiunto. Attendo 60 secondi...")
                    time.sleep(60)
                    continue
                
                response.raise_for_status()
                data = response.json()
                items = data.get("items", [])

                if not items:
                    break # Fine pagine per questo periodo

                for item in items:
                    repo_url = item["html_url"]
                    if repo_url not in all_servers:
                        all_servers[repo_url] = {
                            "name": item["name"],
                            "full_name": item["full_name"],
                            "url": repo_url,
                            "description": item["description"],
                            "stars": item["stargazers_count"],
                            "created_at": item["created_at"],
                            "topics": item.get("topics", [])
                        }

                print(f"  Pagina {page}: trovati {len(items)} nuovi item.")
                
                if len(items) < 100:
                    break # Se la pagina non è piena, abbiamo finito questo periodo
                
                page += 1
                time.sleep(0.5) # Piccola pausa

            except Exception as e:
                print(f"Errore: {e}")
                break
        
        # Avanza alla prossima finestra temporale
        current_date = next_date + timedelta(days=1) 

    # Salvataggio
    results_list = list(all_servers.values())
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results_list, f, indent=4, ensure_ascii=False)

    print(f"\n--- COMPLETATO ---")
    print(f"Totale server unici trovati: {len(results_list)}")
    print(f"Salvati in {OUTPUT_FILE}")

if __name__ == "__main__":
    get_servers_by_time_slice()