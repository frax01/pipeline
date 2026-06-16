import pandas as pd
import json
import os

def remove_urls_from_excel(json_file, excel_file, output_excel):
    # 1. Verifica esistenza file
    if not os.path.exists(json_file):
        print(f"Errore: File JSON '{json_file}' non trovato.")
        return
    if not os.path.exists(excel_file):
        print(f"Errore: File Excel '{excel_file}' non trovato.")
        return

    try:
        # 2. Carica gli URL da rimuovere dal JSON
        print("Caricamento lista URL da rimuovere...")
        with open(json_file, 'r', encoding='utf-8') as f:
            urls_to_remove = set(json.load(f)) # Usiamo un set per ricerca istantanea
        
        print(f"Trovati {len(urls_to_remove)} URL da eliminare nella lista nera.")

        # 3. Carica il file Excel
        print(f"Lettura file Excel: {excel_file} ...")
        # pandas legge la prima riga come intestazione (header) di default
        df = pd.read_excel(excel_file)
        
        # Identifica il nome della prima colonna
        first_col_name = df.columns[0]
        initial_rows = len(df)
        print(f"Il file Excel ha {initial_rows} righe. La colonna degli URL è: '{first_col_name}'")

        # 4. Filtra il DataFrame
        # La tilde (~) significa "NOT".
        # Teniamo le righe dove il valore della prima colonna NON è nella lista urls_to_remove
        df_cleaned = df[~df[first_col_name].isin(urls_to_remove)]

        removed_rows = initial_rows - len(df_cleaned)

        # 5. Salva il risultato
        if removed_rows > 0:
            print(f"Rimozione in corso... Trovate {removed_rows} corrispondenze nel file Excel.")
            df_cleaned.to_excel(output_excel, index=False)
            print("-" * 30)
            print(f"Successo! File pulito salvato come: {output_excel}")
            print(f"Righe originali: {initial_rows}")
            print(f"Righe rimaste: {len(df_cleaned)}")
        else:
            print("-" * 30)
            print("Nessuno degli URL nel file JSON è stato trovato nel file Excel.")
            print("Il file Excel è rimasto invariato (non è stato creato un nuovo file).")

    except Exception as e:
        print(f"Si è verificato un errore: {e}")

if __name__ == "__main__":
    # NOME DEL FILE JSON GENERATO DALLO SCRIPT PRECEDENTE
    JSON_SOURCE = 'urls_to_remove.json' 
    
    # NOME DEL TUO FILE EXCEL ORIGINALE
    EXCEL_SOURCE = '0.0. All servers without duplicates (20369).xlsx'
    
    # NOME DEL FILE EXCEL DI OUTPUT (PULITO)
    EXCEL_OUTPUT = '0.0. All servers_CLEANED.xlsx'

    remove_urls_from_excel(JSON_SOURCE, EXCEL_SOURCE, EXCEL_OUTPUT)