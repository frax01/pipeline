import json
import os

def clean_urls(input_file, clean_output_file, dirty_urls_output_file):
    if not os.path.exists(input_file):
        print(f"Errore: Il file '{input_file}' non è stato trovato.")
        return

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        cleaned_data = []
        dirty_urls = [] # Qui finiranno sia quelli con / che quelli con .git
        
        removed_slash_count = 0
        removed_git_count = 0

        print(f"Analisi di {len(data)} elementi...")

        for entry in data:
            orig = entry.get('original_url', '').strip()
            dup = entry.get('duplicate_url', '').strip()

            # --- CONTROLLO 1: Slash finale ---
            # Se differiscono solo per lo slash finale
            if (orig != dup) and (orig.rstrip('/') == dup.rstrip('/')):
                removed_slash_count += 1
                # Salva quello che ha lo slash
                if orig.endswith('/'):
                    dirty_urls.append(orig)
                else:
                    dirty_urls.append(dup)
                continue # Passa al prossimo elemento, questo è stato rimosso

            # --- CONTROLLO 2: Estensione .git ---
            # Logica: Rimuoviamo ".git" dalla fine di entrambi e vediamo se diventano uguali
            # (e ci assicuriamo che almeno uno dei due avesse .git)
            base_orig = orig[:-4] if orig.endswith('.git') else orig
            base_dup = dup[:-4] if dup.endswith('.git') else dup

            if (orig != dup) and (base_orig == base_dup):
                removed_git_count += 1
                # Salva quello che ha .git
                if orig.endswith('.git'):
                    dirty_urls.append(orig)
                else:
                    dirty_urls.append(dup)
                continue # Passa al prossimo elemento, questo è stato rimosso

            # Se non è né un duplicato di slash né di git, lo teniamo
            cleaned_data.append(entry)

        # Salvataggio file "sporchi" (Slash + Git)
        with open(dirty_urls_output_file, 'w', encoding='utf-8') as f:
            json.dump(dirty_urls, f, indent=4)
        
        # Salvataggio file "pulito"
        with open(clean_output_file, 'w', encoding='utf-8') as f:
            json.dump(cleaned_data, f, indent=4)

        print("-" * 30)
        print("Operazione completata.")
        print(f"Duplicati '/' rimossi: {removed_slash_count}")
        print(f"Duplicati '.git' rimossi: {removed_git_count}")
        print(f"Totale elementi rimossi: {removed_slash_count + removed_git_count}")
        print(f"Elementi validi rimanenti: {len(cleaned_data)}")
        print("-" * 30)
        print(f"Lista URL rimossi salvata in: {dirty_urls_output_file}")
        print(f"Dataset pulito salvato in: {clean_output_file}")

    except json.JSONDecodeError:
        print("Errore: Il file di input non è un JSON valido.")
    except Exception as e:
        print(f"Si è verificato un errore imprevisto: {e}")

# Configurazione
if __name__ == "__main__":
    INPUT_FILE = 'hashAnalysis.json'
    OUTPUT_CLEAN = 'hashAnalysis_cleaned.json'
    OUTPUT_DIRTY = 'urls_to_remove.json' # Contiene sia / che .git

    clean_urls(INPUT_FILE, OUTPUT_CLEAN, OUTPUT_DIRTY)