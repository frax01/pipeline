import pandas as pd
import json
import os

def remove_duplicates_from_excel(json_file, excel_file, output_excel):
    # 1. Verifica esistenza file
    if not os.path.exists(json_file):
        print(f"Errore: File JSON '{json_file}' non trovato.")
        return
    if not os.path.exists(excel_file):
        print(f"Errore: File Excel '{excel_file}' non trovato. Assicurati di aver eseguito lo script precedente.")
        return

    try:
        # 2. Carica i 'duplicate_url' dal JSON pulito
        print(f"Lettura file JSON duplicati: {json_file} ...")
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Estraiamo solo il campo "duplicate_url" da ogni oggetto
        # Questi sono gli URL che vogliamo eliminare dal file Excel
        urls_to_remove = set()
        for entry in data:
            if 'duplicate_url' in entry:
                urls_to_remove.add(entry['duplicate_url'])
        
        print(f"Trovati {len(urls_to_remove)} URL unici marcati come duplicati da eliminare.")

        # 3. Carica il file Excel (quello già pulito dallo step precedente)
        print(f"Lettura file Excel: {excel_file} ...")
        df = pd.read_excel(excel_file)
        
        # Identifica la prima colonna
        first_col_name = df.columns[0]
        initial_rows = len(df)
        print(f"Righe attuali nel file Excel: {initial_rows}")

        # 4. Filtra via i duplicati
        # Manteniamo le righe dove l'URL NON è nella lista dei duplicati
        df_final = df[~df[first_col_name].isin(urls_to_remove)]

        removed_count = initial_rows - len(df_final)

        # 5. Salva il risultato finale
        if removed_count > 0:
            print(f"Rimozione in corso... Eliminati altri {removed_count} URL.")
            df_final.to_excel(output_excel, index=False)
            print("-" * 30)
            print(f"COMPLETATO! File finale salvato come: {output_excel}")
            print(f"Righe totali finali: {len(df_final)}")
        else:
            print("-" * 30)
            print("Nessun URL del file JSON è stato trovato nel file Excel.")
            print("Forse sono già stati rimossi o i link non corrispondono esattamente.")
            # Salviamo comunque per coerenza, se vuoi
            # df_final.to_excel(output_excel, index=False)

    except Exception as e:
        print(f"Si è verificato un errore: {e}")

if __name__ == "__main__":
    # FILE DI INPUT
    # Il file JSON creato dal primo script (senza i casi di slash/.git)
    JSON_CLEANED = 'hashAnalysis_cleaned.json' 
    
    # Il file Excel creato dal secondo script
    EXCEL_INPUT = '0.0. All servers_CLEANED.xlsx'
    
    # FILE DI OUTPUT
    EXCEL_FINAL = '0.0. All servers_FINAL.xlsx'

    remove_duplicates_from_excel(JSON_CLEANED, EXCEL_INPUT, EXCEL_FINAL)