import json
import re

def estrai_link_da_evidence(input_json, output_txt):
    # Regex per catturare URL che iniziano con http o https. 
    # Si ferma quando incontra spazi, apici singoli, doppi o parentesi angolari.
    regex_url = re.compile(r"https?://[^\s'\"<>]+")
    
    link_trovati = set() # Usiamo un 'set' per evitare di salvare link duplicati
    
    try:
        # 1. Apri e leggi il file JSON
        with open(input_json, 'r', encoding='utf-8') as file:
            dati = json.load(file)
            
        # 2. Naviga nella lista 'findings'
        if 'findings' in dati:
            for elemento in dati['findings']:
                # Usiamo 'or ""' in modo che se il risultato è None, diventa una stringa vuota
                evidence = elemento.get('evidence') or ""
                
                # 3. Trova tutti i match con la regex
                match = regex_url.findall(evidence)
                for url in match:
                    # Pulizia finale per rimuovere virgole o parentesi alla fine della stringa
                    url_pulito = url.rstrip(',);]')
                    link_trovati.add(url_pulito)
                    
        # 4. Scrivi i risultati sul file di testo
        with open(output_txt, 'w', encoding='utf-8') as file_out:
            for link in sorted(link_trovati):
                file_out.write(link + '\n')
                
        print(f"✅ Estrazione completata con successo!")
        print(f"🔗 Trovati {len(link_trovati)} link unici.")
        print(f"📄 Risultati salvati in: {output_txt}")
        
    except FileNotFoundError:
        print(f"❌ Errore: Il file '{input_json}' non è stato trovato.")
    except json.JSONDecodeError:
        print(f"❌ Errore: Il file '{input_json}' non è un JSON valido.")

# Avvia la funzione con i nomi dei tuoi file
estrai_link_da_evidence('C:\\Users\\francesco\\Desktop\\pipeline\\analysisAllData\\mcp_watch\\protocol-violation\\protocol_violation_high.json', 'C:\\Users\\francesco\\Desktop\\pipeline\\analysisAllData\\mcp_watch\\protocol-violation\\link_estratti.txt')