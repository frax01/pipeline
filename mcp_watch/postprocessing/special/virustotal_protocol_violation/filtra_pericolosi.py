import json

FILE_INPUT = "risultati_virustotal.jsonl"
FILE_OUTPUT = "link_pericolosi.txt"

def estrai_link_malevoli():
    link_trovati = []
    
    try:
        # Apriamo il file con i risultati
        with open(FILE_INPUT, 'r', encoding='utf-8') as f:
            for riga in f:
                # Trasformiamo la riga di testo in un dizionario Python
                try:
                    dati = json.loads(riga)
                    
                    # Recuperiamo il numero di segnalazioni "malicious" (se non c'è, di default è 0)
                    segnalazioni_malicious = dati.get("stats", {}).get("malicious", 0)
                    
                    # Se è almeno 1, lo salviamo
                    if segnalazioni_malicious >= 1:
                        link_trovati.append(dati["url"])
                        
                except json.JSONDecodeError:
                    # Ignoriamo eventuali righe corrotte
                    continue
                    
        # Salviamo i risultati nel nuovo file di testo
        with open(FILE_OUTPUT, 'w', encoding='utf-8') as out_file:
            for link in link_trovati:
                out_file.write(link + "\n")
                
        print("Filtraggio completato!")
        print(f"Trovati {len(link_trovati)} link con almeno 1 segnalazione 'malicious'.")
        print(f"Salvati nel file: {FILE_OUTPUT}")
        
    except FileNotFoundError:
        print(f"Errore: Il file {FILE_INPUT} non è stato trovato. Assicurati di essere nella cartella giusta.")

# Avvia la funzione
estrai_link_malevoli()