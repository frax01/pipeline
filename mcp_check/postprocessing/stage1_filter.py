#!/usr/bin/env python3
"""
Filter per mcp-check: estrae i finding più interessanti dai risultati di conformance testing.

mcp-check NON è uno scanner di sicurezza — è un test harness che verifica la conformità
al protocollo MCP. I "finding" sono errori di compliance, non vulnerabilità.

Categorie INTERESSANTI (da tenere):
  - panic_or_crash: crash/panic nel server (bug reali, possibili DoS)
  - schema_violation: schema JSON invalidi nelle tool definition
  - unauthorized_or_auth_missing: errori di autenticazione (server che richiedono auth)
  - invalid_arguments: errori nella gestione degli argomenti
  - warnings: tool senza descrizione, naming issues
  - method_not_found: metodi MCP non implementati

Categorie NOISE (da scartare):
  - not_connected: il server non si è avviato (Docker, dipendenze, ecc.)
  - connection_refused: connessione rifiutata
  - timeout: timeout nella connessione/risposta
  - file_not_found: file/comando non trovato
  - docker_missing: Docker non installato sulla VM
  - macos_specific_failed: fallimenti specifici macOS (le VM sono Linux)
  - other_errors: errori generici (troppo rumorosi, da filtrare selettivamente)

Uso:
  python stage1_filter.py                    # Filtra tutto
  python stage1_filter.py --dry-run          # Solo statistiche, non scrive file
  python stage1_filter.py --category schema_violation  # Solo una categoria
"""

import json
import os
import sys
import re
from collections import defaultdict
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ============================================================================
# CONFIGURAZIONE
# ============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PHASES = ['handshake', 'tool_discovery', 'tool_invocation']

# Categorie da SCARTARE completamente (sono noise infrastrutturale)
SKIP_CATEGORIES = {
    'not_connected',        # 73K+ entries - server non avviato
    'connection_refused',   # connessione rifiutata
    'timeout',              # timeout (infrastruttura)
    'file_not_found',       # file/comando non trovato
    'docker_missing',       # Docker non presente sulla VM
    'macos_specific_failed', # test specifici macOS su VM Linux
}

# Categorie da TENERE (interessanti per l'analisi)
KEEP_CATEGORIES = {
    'panic_or_crash',               # crash/panic — bug reali
    'schema_violation',             # schema invalidi
    'unauthorized_or_auth_missing', # problemi di auth
    'invalid_arguments',            # gestione argomenti errata
    'method_not_found',             # metodi MCP non implementati
    'warnings',                     # quality issues (tool senza descrizione)
    'other_errors',                 # filtrati selettivamente
}

# ============================================================================
# FILTRI PER other_errors (la categoria più rumorosa dopo le infrastrutturali)
# ============================================================================

def filter_other_errors(entry):
    """
    Filtra other_errors tenendo solo gli errori interessanti.
    Scarta:
      - Errori di import/modulo (dipendenze mancanti)
      - Errori di connessione/rete nascosti in other_errors
      - Errori di configurazione ambiente
    Tiene:
      - Errori runtime nel server
      - Errori di protocollo MCP
      - Errori di validazione
    """
    errors = entry.get('errors', [])
    filtered_errors = []

    for err in errors:
        msg = err.get('message', '')

        # SCARTA: errori di import/modulo (dipendenze mancanti)
        if re.search(r'ModuleNotFoundError|ImportError|Cannot find module|Module not found', msg):
            continue

        # SCARTA: errori di connessione nascosti
        if re.search(r'ECONNREFUSED|ECONNRESET|EPIPE|ETIMEDOUT|ENOTFOUND|EADDRINUSE', msg):
            continue

        # SCARTA: "Connection closed" — è noise di trasporto (826 entries)
        if re.search(r'Connection closed', msg):
            continue

        # SCARTA: "Already connected to a transport" — bug SDK, non del server (72 entries)
        if re.search(r'Already connected to a transport', msg):
            continue

        # SCARTA: errori di avvio server
        if re.search(r'Server process (exited|crashed|failed to start)|spawn .* ENOENT', msg):
            continue

        # SCARTA: errori npm/node/python setup
        if re.search(r'npm ERR|pip install|requirements\.txt|package\.json not found', msg):
            continue

        # SCARTA: errori di permessi file
        if re.search(r'EACCES|Permission denied|EPERM', msg):
            continue

        # SCARTA: errori di parsing JSON generici dal transport
        if re.search(r'Unexpected end of JSON|Unexpected token.*in JSON', msg):
            continue

        # SCARTA: errori di encoding
        if re.search(r'UnicodeDecodeError|UnicodeEncodeError|codec can\'t', msg):
            continue

        # SCARTA: server che stampa help/usage invece di avviarsi
        if re.search(r'Usage:|--help|unrecognized arguments', msg):
            continue

        # SCARTA: errori di variabili d'ambiente mancanti
        if re.search(r'(Missing|Required).*(API.?KEY|TOKEN|SECRET|environment)', msg, re.IGNORECASE):
            continue

        # SCARTA: "fetch failed" — errori di rete generici
        if re.search(r'fetch failed$', msg):
            continue

        # SCARTA: errori Playwright/browser (test su server browser-based)
        if re.search(r'browserType\.launch|Executable doesn\'t exist.*playwright', msg):
            continue

        # SCARTA: errori di connessione a servizi esterni (DB, API)
        if re.search(r'Failed to connect to database.*getaddrinfo|EAI_AGAIN', msg):
            continue

        # SCARTA: configurazione servizi mancante
        if re.search(r'configuration missing|Please (make sure|set|configure)', msg, re.IGNORECASE):
            continue

        # SCARTA: "Not authenticated. Call .* first" — auth mancante, già in unauthorized
        if re.search(r'Not authenticated\. Call .* first', msg):
            continue

        # SCARTA: protocol version non supportata
        if re.search(r"Server's protocol version is not supported", msg):
            continue

        # SCARTA: "Server not initialized"
        if re.search(r'Server not initialized', msg):
            continue

        # SCARTA: API KEY/config mancanti in errori runtime
        if re.search(r'(API.?KEY|API.?URL|API.?TOKEN).*(not set|is required|environment)', msg, re.IGNORECASE):
            continue
        if re.search(r'client not initialized.*Set ', msg, re.IGNORECASE):
            continue

        # SCARTA: errori interni vuoti o generici
        if re.search(r'^MCP error -32603:\s*$', msg):
            continue
        if msg.strip() in ('MCP error -32603: Internal error', 'MCP error -32603: Unknown error occurred',
                           'MCP error -32603: Tool execution failed'):
            continue

        # SCARTA: errori _zod/_def — bug nel SDK, non nel server
        if re.search(r"reading '_(zod|def)'", msg):
            continue

        # SCARTA: spawn ENOTDIR
        if re.search(r'spawn ENOTDIR', msg):
            continue

        # SCARTA: "Event 'test' not found" — artefatto di test
        if re.search(r"Event 'test' not found", msg):
            continue

        filtered_errors.append(err)

    if filtered_errors:
        entry_copy = dict(entry)
        entry_copy['errors'] = filtered_errors
        return entry_copy
    return None


def filter_schema_violation(entry):
    """
    Filtra schema_violation.
    Tiene tutto — gli schema invalidi sono sempre interessanti.
    Eventualmente filtra solo duplicati o messaggi troppo generici.
    """
    errors = entry.get('errors', [])
    filtered_errors = []

    for err in errors:
        msg = err.get('message', '')

        # SCARTA: messaggi vuoti
        if not msg.strip():
            continue

        filtered_errors.append(err)

    if filtered_errors:
        entry_copy = dict(entry)
        entry_copy['errors'] = filtered_errors
        return entry_copy
    return None


def filter_invalid_arguments(entry):
    """
    Filtra invalid_arguments.
    Tiene tutto — indicano bug nella validazione degli input.
    """
    return entry


def filter_method_not_found(entry):
    """
    Filtra method_not_found.
    Tiene solo casi dove il server non implementa metodi core MCP.
    Scarta errori da metodi custom/estensioni.
    """
    errors = entry.get('errors', [])
    filtered_errors = []

    for err in errors:
        msg = err.get('message', '')

        # I metodi core MCP che dovrebbero sempre esistere
        # Se mancano, è un problema di conformance reale
        if re.search(r'tools/list|tools/call|initialize|ping|resources/', msg):
            filtered_errors.append(err)
            continue

        # Tieni anche errori MCP con codici standard
        if re.search(r'MCP error -32601', msg):  # Method not found standard
            filtered_errors.append(err)
            continue

        # Scarta il resto (metodi custom, estensioni non standard)
        filtered_errors.append(err)

    if filtered_errors:
        entry_copy = dict(entry)
        entry_copy['errors'] = filtered_errors
        return entry_copy
    return None


def filter_unauthorized(entry):
    """
    Filtra unauthorized_or_auth_missing.
    Tiene tutto — indica server che richiedono auth (informazione utile).
    """
    return entry


def filter_warnings(entry):
    """
    Filtra warnings.
    Tiene tutto — sono quality issues (tool senza descrizione, ecc.)
    """
    return entry


def filter_panic_or_crash(entry):
    """
    Filtra panic_or_crash.
    Tiene TUTTO — crash e panic sono sempre interessanti.
    """
    return entry


# Mappa categoria -> funzione filtro
CATEGORY_FILTERS = {
    'panic_or_crash': filter_panic_or_crash,
    'schema_violation': filter_schema_violation,
    'unauthorized_or_auth_missing': filter_unauthorized,
    'invalid_arguments': filter_invalid_arguments,
    'method_not_found': filter_method_not_found,
    'warnings': filter_warnings,
    'other_errors': filter_other_errors,
}


# ============================================================================
# FUNZIONI PRINCIPALI
# ============================================================================

def load_json_files(directory):
    """Carica tutti i file JSON da una directory."""
    entries = []
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith('.json'):
            continue
        filepath = os.path.join(directory, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for entry in data.get('entries', []):
                entry['_source_file'] = filename
                entries.append(entry)
        except Exception as e:
            print(f"  ERRORE leggendo {filepath}: {e}")
    return entries


def process_category(phase, category, entries, dry_run=False):
    """Processa una categoria: applica filtri e salva risultati."""
    filter_fn = CATEGORY_FILTERS.get(category)
    if not filter_fn:
        return None

    filtered = []
    for entry in entries:
        result = filter_fn(entry)
        if result is not None:
            filtered.append(result)

    stats = {
        'phase': phase,
        'category': category,
        'original': len(entries),
        'filtered': len(filtered),
        'removed': len(entries) - len(filtered),
        'removal_rate': f"{(1 - len(filtered)/len(entries))*100:.1f}%" if entries else "N/A"
    }

    if not dry_run and filtered:
        # Crea directory filtered
        filtered_dir = os.path.join(BASE_DIR, phase, category, 'filtered')
        os.makedirs(filtered_dir, exist_ok=True)

        # Salva JSON filtrato
        output_file = os.path.join(filtered_dir, f'{category}_filtered.json')
        output_data = {
            'total': len(filtered),
            'phase': phase,
            'category': category,
            'filter_date': datetime.now().isoformat(),
            'entries': filtered
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        stats['output_file'] = output_file

    return stats


def generate_category_report(phase, category, entries, filtered_entries, output_dir):
    """Genera report .md per una categoria filtrata."""
    report_path = os.path.join(output_dir, f'{category}_analysis.md')

    # Statistiche per linguaggio
    lang_counts = defaultdict(int)
    for e in filtered_entries:
        lang_counts[e.get('language', 'unknown')] += 1

    # Raggruppa per tipo di errore/test
    error_types = defaultdict(list)
    for e in filtered_entries:
        for err in e.get('errors', e.get('warnings', [])):
            test = err.get('test', 'unknown')
            error_types[test].append({
                'server': e.get('server_name', '?'),
                'url': e.get('server_url', '?'),
                'language': e.get('language', '?'),
                'message': err.get('message', ''),
                'type': err.get('type', ''),
            })

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f"# {phase}/{category} - Analisi Finding Filtrati\n\n")
        f.write(f"**Data analisi**: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
        f.write(f"## Statistiche\n\n")
        f.write(f"| Metrica | Valore |\n|---------|--------|\n")
        f.write(f"| Finding originali | {len(entries)} |\n")
        f.write(f"| Finding filtrati | {len(filtered_entries)} |\n")
        f.write(f"| Rimossi | {len(entries) - len(filtered_entries)} ({(1 - len(filtered_entries)/max(len(entries),1))*100:.1f}%) |\n\n")

        f.write(f"## Distribuzione per linguaggio\n\n")
        f.write(f"| Linguaggio | Count |\n|------------|-------|\n")
        for lang, count in sorted(lang_counts.items(), key=lambda x: -x[1]):
            f.write(f"| {lang} | {count} |\n")
        f.write("\n")

        f.write(f"## Finding per tipo di test\n\n")
        for test_name, findings in sorted(error_types.items(), key=lambda x: -len(x[1])):
            f.write(f"### `{test_name}` ({len(findings)} finding)\n\n")

            # Mostra fino a 10 esempi per test
            shown = min(len(findings), 10)
            for i, finding in enumerate(findings[:shown]):
                f.write(f"**{i+1}. [{finding['server']}]({finding['url']})** ({finding['language']})\n")
                f.write(f"- Type: `{finding['type']}`\n") if finding['type'] else None
                # Tronca messaggi troppo lunghi
                msg = finding['message']
                if len(msg) > 500:
                    msg = msg[:500] + "..."
                f.write(f"- Message: `{msg}`\n\n")

            if len(findings) > shown:
                f.write(f"*... e altri {len(findings) - shown} finding simili*\n\n")

        # Sezione interpretazione
        f.write(f"## Interpretazione\n\n")
        if category == 'panic_or_crash':
            f.write("I **panic/crash** indicano bug reali nel codice del server. "
                    "Un server MCP che va in panic su input validi è potenzialmente "
                    "vulnerabile a DoS. Tutti i finding in questa categoria sono **veri positivi**.\n\n")
        elif category == 'schema_violation':
            f.write("Le **schema violation** indicano tool con schema JSON non valido "
                    "secondo la specifica MCP/JSON Schema Draft-07. Questo può causare "
                    "problemi di interoperabilità con i client MCP e potenzialmente "
                    "comportamenti inattesi. La maggior parte sono **veri positivi** di conformance.\n\n")
        elif category == 'unauthorized_or_auth_missing':
            f.write("Gli errori di **auth** indicano server che richiedono autenticazione "
                    "per funzionare. Non sono vulnerabilità in sé, ma sono informativi: "
                    "mostrano quali server hanno un layer di auth attivo.\n\n")
        elif category == 'invalid_arguments':
            f.write("Gli **invalid_arguments** indicano server che non gestiscono "
                    "correttamente argomenti non validi o mancanti. Possono indicare "
                    "input validation insufficiente.\n\n")
        elif category == 'warnings':
            f.write("I **warnings** sono issue di qualità: tool senza descrizione, "
                    "naming non standard, ecc. Non sono errori ma indicano scarsa "
                    "qualità dell'implementazione MCP.\n\n")
        elif category == 'method_not_found':
            f.write("I **method_not_found** indicano server che non implementano "
                    "metodi MCP richiesti dalla specifica. Possono indicare "
                    "implementazioni parziali o non conformi.\n\n")
        elif category == 'other_errors':
            f.write("Gli **other_errors** filtrati sono errori runtime che non rientrano "
                    "nelle altre categorie. Dopo aver rimosso errori di setup/infrastruttura, "
                    "rimangono errori applicativi potenzialmente interessanti.\n\n")

    return report_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Filter mcp-check results')
    parser.add_argument('--dry-run', action='store_true', help='Solo statistiche')
    parser.add_argument('--category', type=str, help='Filtra solo questa categoria')
    parser.add_argument('--phase', type=str, help='Filtra solo questa fase')
    args = parser.parse_args()

    print("=" * 70)
    print("  FILTRO MCP-CHECK - Estrazione finding interessanti")
    print("=" * 70)
    print()

    total_original = 0
    total_filtered = 0
    all_stats = []

    phases = [args.phase] if args.phase else PHASES

    for phase in phases:
        phase_dir = os.path.join(BASE_DIR, phase)
        if not os.path.isdir(phase_dir):
            continue

        print(f"\n{'='*50}")
        print(f"  FASE: {phase}")
        print(f"{'='*50}")

        for category in sorted(os.listdir(phase_dir)):
            cat_dir = os.path.join(phase_dir, category)
            if not os.path.isdir(cat_dir):
                continue
            if category == 'filtered':
                continue

            # Filtro per categoria se specificato
            if args.category and category != args.category:
                continue

            # Skip categorie noise
            if category in SKIP_CATEGORIES:
                entries = load_json_files(cat_dir)
                print(f"\n  SKIP {category}: {len(entries)} entries (noise infrastrutturale)")
                total_original += len(entries)
                continue

            # Categorie da processare
            if category not in KEEP_CATEGORIES:
                entries = load_json_files(cat_dir)
                print(f"\n  SKIP {category}: {len(entries)} entries (categoria sconosciuta)")
                total_original += len(entries)
                continue

            print(f"\n  >> {category}")
            entries = load_json_files(cat_dir)
            print(f"     Caricati {len(entries)} entries")

            stats = process_category(phase, category, entries, dry_run=args.dry_run)
            if stats:
                total_original += stats['original']
                total_filtered += stats['filtered']
                all_stats.append(stats)
                print(f"     Filtrati: {stats['filtered']}/{stats['original']} "
                      f"(rimossi {stats['removed']}, {stats['removal_rate']})")

                # Genera report .md
                if not args.dry_run and stats['filtered'] > 0:
                    filtered_dir = os.path.join(cat_dir, 'filtered')
                    # Ricarica filtered entries dal JSON
                    filtered_file = os.path.join(filtered_dir, f'{category}_filtered.json')
                    with open(filtered_file, 'r', encoding='utf-8') as ff:
                        filtered_data = json.load(ff)
                    report = generate_category_report(
                        phase, category, entries,
                        filtered_data['entries'], filtered_dir
                    )
                    print(f"     Report: {os.path.relpath(report, BASE_DIR)}")

    # Statistiche finali
    print(f"\n{'='*70}")
    print(f"  RIEPILOGO FINALE")
    print(f"{'='*70}")
    print(f"\n  Finding originali totali (cat. interessanti): {total_original}")
    print(f"  Finding filtrati (tenuti): {total_filtered}")
    print(f"  Finding rimossi: {total_original - total_filtered}")
    if total_original > 0:
        print(f"  Tasso di riduzione: {(1 - total_filtered/total_original)*100:.1f}%")

    print(f"\n  Dettaglio per categoria:")
    print(f"  {'Fase':<20} {'Categoria':<30} {'Orig':>8} {'Filt':>8} {'Rimossi':>8}")
    print(f"  {'-'*18:<20} {'-'*28:<30} {'-'*6:>8} {'-'*6:>8} {'-'*6:>8}")
    for s in all_stats:
        print(f"  {s['phase']:<20} {s['category']:<30} {s['original']:>8} "
              f"{s['filtered']:>8} {s['removed']:>8}")

    if args.dry_run:
        print(f"\n  (DRY RUN - nessun file scritto)")
    else:
        print(f"\n  File scritti nelle directory filtered/ di ogni categoria.")

    # Genera report globale
    if not args.dry_run and all_stats:
        generate_global_report(all_stats)
        print(f"  Report globale: filter_analysis_report.md")

    print()


def generate_global_report(all_stats):
    """Genera il report globale con tutte le statistiche."""
    report_path = os.path.join(BASE_DIR, 'filter_analysis_report.md')

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# MCP-Check Filter - Report Analisi\n\n")
        f.write(f"**Data**: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")

        f.write("## Cosa è mcp-check\n\n")
        f.write("mcp-check è un **test harness di conformance** per il protocollo MCP. "
                "NON è uno scanner di sicurezza. Testa:\n\n")
        f.write("1. **Handshake**: connessione, initialize, capability negotiation\n")
        f.write("2. **Tool Discovery**: enumerazione tool, validazione schema JSON\n")
        f.write("3. **Tool Invocation**: esecuzione tool con input validi e invalidi\n\n")

        f.write("## Categorie scartate (noise)\n\n")
        f.write("| Categoria | Motivo |\n|-----------|--------|\n")
        f.write("| `not_connected` | Server non avviato (dipendenze, Docker, config) |\n")
        f.write("| `connection_refused` | Connessione TCP rifiutata |\n")
        f.write("| `timeout` | Timeout connessione/risposta |\n")
        f.write("| `file_not_found` | File/comando non trovato |\n")
        f.write("| `docker_missing` | Docker non installato sulla VM |\n")
        f.write("| `macos_specific_failed` | Test macOS su VM Linux |\n\n")

        f.write("## Categorie filtrate\n\n")
        f.write("| Fase | Categoria | Originali | Filtrati | Rimossi | Riduzione |\n")
        f.write("|------|-----------|-----------|----------|---------|----------|\n")

        total_orig = sum(s['original'] for s in all_stats)
        total_filt = sum(s['filtered'] for s in all_stats)

        for s in all_stats:
            f.write(f"| {s['phase']} | `{s['category']}` | {s['original']} | "
                    f"{s['filtered']} | {s['removed']} | {s['removal_rate']} |\n")

        f.write(f"| **TOTALE** | | **{total_orig}** | **{total_filt}** | "
                f"**{total_orig - total_filt}** | "
                f"**{(1 - total_filt/max(total_orig,1))*100:.1f}%** |\n\n")

        f.write("## Categorie più interessanti\n\n")
        f.write("### 1. `panic_or_crash`\n")
        f.write("I crash/panic sono i finding più critici. Indicano bug reali nel server "
                "che potrebbero essere sfruttati per DoS. Tutti i server Go con panic "
                "recovered mostrano type assertion failure su input mancanti.\n\n")

        f.write("### 2. `schema_violation`\n")
        f.write("Schema JSON non validi nelle tool definition. Impattano l'interoperabilità "
                "con client MCP e possono causare comportamenti inattesi nell'LLM.\n\n")

        f.write("### 3. `invalid_arguments`\n")
        f.write("Server che non gestiscono correttamente input invalidi. Possono indicare "
                "mancanza di input validation.\n\n")

        f.write("### 4. `unauthorized_or_auth_missing`\n")
        f.write("Server con layer di autenticazione. Informativi per capire quali server "
                "proteggono le loro API.\n\n")

        f.write("### 5. `warnings`\n")
        f.write("Issue di qualità: tool senza descrizione, naming inconsistente. "
                "Impattano l'usabilità da parte dell'LLM.\n\n")

        f.write("## Come usare i risultati\n\n")
        f.write("I file filtrati si trovano in `<fase>/<categoria>/filtered/`:\n")
        f.write("- `*_filtered.json`: finding filtrati in formato JSON\n")
        f.write("- `*_analysis.md`: report di analisi con esempi e interpretazione\n")


if __name__ == '__main__':
    main()
