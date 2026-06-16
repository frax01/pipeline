import vt
import time
import json
import os

API_KEY = os.environ.get("VT_API_KEY", "")  # chiave VirusTotal via variabile d'ambiente
FILE_INPUT = "link_estratti.txt"
FILE_OUTPUT = "risultati_virustotal.jsonl"  # Usiamo JSONL (JSON Lines) per salvare un record per riga

# Funzione "salva-vita" per convertire gli oggetti speciali di VirusTotal in dizionari normali
def vt_serializer(obj):
    if hasattr(obj, 'items'):
        return dict(obj)
    return str(obj)

def avvia_scansione_massiva():
    # 1. Leggiamo tutti i link dal file
    try:
        with open(FILE_INPUT, 'r', encoding='utf-8') as f:
            tutti_i_link = [linea.strip() for linea in f if linea.strip()]
    except FileNotFoundError:
        print(f"❌ Errore: File {FILE_INPUT} non trovato.")
        return

    # 2. Controlliamo quali link abbiamo GIA' analizzato in passato
    link_gia_fatti = set()
    if os.path.exists(FILE_OUTPUT):
        with open(FILE_OUTPUT, 'r', encoding='utf-8') as f:
            for linea in f:
                try:
                    dati = json.loads(linea)
                    link_gia_fatti.add(dati['url'])
                except:
                    pass

    # Filtriamo la lista per tenere solo i link ancora da fare
    link_da_fare = [link for link in tutti_i_link if link not in link_gia_fatti]
    
    print(f"📊 Totale link nel file: {len(tutti_i_link)}")
    print(f"✅ Link già analizzati: {len(link_gia_fatti)}")
    print(f"⏳ Link da analizzare ora: {len(link_da_fare)}\n")

    if not link_da_fare:
        print("🎉 Tutti i link sono già stati analizzati!")
        return

    # 3. Iniziamo il ciclo di scansione
    with vt.Client(API_KEY) as client:
        with open(FILE_OUTPUT, 'a', encoding='utf-8') as out_file:
            
            for index, url in enumerate(link_da_fare):
                print(f"[{index + 1}/{len(link_da_fare)}] Analizzando: {url}")
                
                try:
                    # Invia il link a VirusTotal
                    analysis = client.scan_url(url)
                    
                    # Polling: aspettiamo i risultati
                    while True:
                        time.sleep(16)
                        analysis = client.get_object(f"/analyses/{analysis.id}")
                        
                        if analysis.status == "completed":
                            break
                        print("   ...attendo il completamento dell'analisi...")

                    dettagli_completi = analysis.to_dict()
                    
                    # Creiamo il record da salvare (convertendo esplicitamente stats in un dict standard)
                    record = {
                        "url": url,
                        "timestamp": time.time(),
                        "stats": dict(analysis.stats),    
                        "dettagli": dettagli_completi
                    }
                    
                    # Scriviamo il record istruendo json su come gestire oggetti sconosciuti (default=vt_serializer)
                    out_file.write(json.dumps(record, default=vt_serializer) + "\n")
                    out_file.flush()
                    
                    malware_trovati = analysis.stats.get('malicious', 0)
                    print(f"   => Finito! Segnalazioni malevole: {malware_trovati}")
                    
                except vt.error.APIError as e:
                    print(f"   ❌ Errore API con {url}: {e}")
                    if "QuotaExceededError" in str(e):
                        print("\n🛑 Hai superato il limite di richieste di VirusTotal!")
                        print("Lo script si ferma qui. I progressi sono stati salvati.")
                        break
                    time.sleep(16)

                except Exception as e:
                    print(f"   ❌ Errore generico con {url}: {e}")
                    time.sleep(16)

# Esegui la funzione
avvia_scansione_massiva()