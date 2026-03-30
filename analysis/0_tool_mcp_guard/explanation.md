Analisi dei Risultati di MCP Guard - 60.205 Server Scansionati
Panoramica Generale
Hai scansionato 60.205 server MCP, di cui 56.407 (93.7%) analizzati con successo da mcp-guard. I restanti sono probabilmente repository non-MCP o fallimenti. Il dataset copre 5 linguaggi: Node.js (41%), Python (36%), Go (3%), Docker (2%), unknown (19%).

Le 5 Vulnerabilità Più Diffuse
#	Vulnerabilità	%	Gravità tipica
1	Command Injection (code execution)	20.6%	CRITICAL
2	Insecure localhost endpoint (SSRF)	13.4%	HIGH
3	MCP Tool missing input validation	8.3%	MEDIUM
4	Hardcoded credentials	7.3%	HIGH
5	Path traversal	6.9%	HIGH
Queste 5 categorie coprono il 56.5% di tutte le vulnerabilità trovate — un pattern chiaro e preoccupante.

1. Command Injection (20.6%) — Il problema dominante
Oltre 1 server su 5 ha un rischio di code execution. Nel codice sorgente, la detection avviene in mcp_scanner.py:1860 (_find_command_injection_contextual):

# Linee 1866-1878: Pattern language-specific
command_patterns = {
    'python': [r'subprocess\.(run|call|Popen)\s*\(', r'os\.system\s*\(', r'os\.popen\s*\('],
    'nodejs': [r'child_process\.(exec|spawn|execSync|spawnSync)\s*\('],
    'go': [r'exec\.Command\s*\(']
}

La funzione _uses_external_input_contextual (linea 1940) verifica se i parametri del comando derivano da input utente cercando indicatori come request, params, args, input, tool_call, arguments. Il 20.6% significa che moltissimi server MCP passano input utente direttamente a comandi di sistema senza sanitizzazione.

Il fatto che questa sia anche la categoria dominante nel real fuzzing (14.832 casi in categories_real_fuzzing) conferma che non sono falsi positivi statici — molti server accettano realmente payload di injection durante il test dinamico.

2. Insecure Localhost Endpoint / SSRF (13.4%)
Rilevato solo nell'analisi dinamica (categories_dynamic: 74.988 casi). Questo suggerisce che molti server MCP espongono endpoint su localhost senza protezione, rendendoli vulnerabili a Server-Side Request Forgery. La detection avviene nell'analisi dei pattern di security in _analyze_server_security_patterns (linea ~2798), che controlla le configurazioni di binding e gli endpoint esposti.

3. MCP Tool Missing Input Validation (8.3%)
Rilevato dall'analisi statica (categories_static: 46.370 casi — il più alto in assoluto). Nel codice, _check_mcp_tool_validation (linea 1342) cerca handler di tool che non validano i parametri:

# Linea 1348-1353: Pattern per tool handler senza validazione
'pattern': r'(?i)(def|function|async\s+function)\s+(\w*tool\w*|\w*call\w*)\s*\([^)]*\)',
'check_type': 'input_validation',
'title': 'MCP Tool Missing Input Validation'

La verifica _has_comprehensive_input_validation (linea 1389) controlla se esiste validazione nelle vicinanze. 46.370 finding statici su 56.407 server significano che quasi ogni server ha almeno un tool handler senza validazione — un problema sistemico dell'ecosistema MCP.

4. Distribuzione per Severità
MEDIUM:  49.83%  (279.875 vulnerabilità)
CRITICAL: 31.04% (174.352)
HIGH:     19.00% (106.715)
LOW:       0.12% (690)

561.632 vulnerabilità totali, media di 9.96 per server. Il fatto che il 50% delle vulnerabilità siano CRITICAL+HIGH è significativo. Il sistema di scoring usa CVSS v4.0 e AIVSS (linee 108-124 del dataclass Vulnerability), con mapping CWE definiti in simple_vulnerability_scoring.py.

5. Static vs Dynamic vs Fuzzing
Tipo Analisi	Server analizzati	%
Static	56.407	100%
Dynamic (simulato)	45.178	80.1%
Real Fuzzing (server avviato)	11.229	19.9%
Robustness Fuzzing	9.094	16.1%
Solo il 19.9% dei server è stato effettivamente avviato e testato con fuzzing reale. Questo è controllato in _run_real_dynamic_fuzzing (linea 2769): se il server non si avvia, il codice cade in _perform_enhanced_static_dynamic_analysis (linea 2871) — analisi statica potenziata che simula finding dinamici. Ecco perché categories_dynamic ha numeri molto più alti di categories_real_fuzzing.

Il dato chiave: quando il server viene effettivamente avviato (real fuzzing), le vulnerabilità trovate sono comunque gravi:

Path traversal: 15.562 (quasi tutti i server avviati)
Command injection: 14.832
Timeout/DoS: 8.773
Authorization bypass: 5.952
6. Failure Rate
3.797 server (6.31%) hanno fallito la scansione:

execution_timeout: 1.764 (46.5%) — server troppo lenti o bloccati
clone_failed: 1.478 (38.9%) — repo non più disponibili
config_build_failed: 358 — errori di build
prepare_timeout: 161 — setup troppo lungo
Il timeout di esecuzione è gestito da _run_with_timeout (linea 169), con risultati parziali salvati in _partial_results per non perdere i dati già raccolti:

# Linea 176-178
result_container = {}
exception_container = {}

7. Categorie MCP-Specifiche (Solo Analisi Statica)
Le più interessanti per l'ecosistema MCP:

Categoria	Occorrenze
MCP Tool Missing Input Validation	46.370
Unsafe MCP Resource Access	33.142
Unsafe MCP JSON-RPC Message Handling	30.551
MCP Handler Missing Authentication	20.097
MCP Missing Capability Validation	19.971
Questi numeri rivelano che la maggioranza dei server MCP manca di controlli di sicurezza fondamentali. La detection di _check_mcp_resource_safety e _check_mcp_auth_bypass (linee 1297-1300) trova che quasi ogni server ha pattern di accesso risorse non sicuri.

8. Sensitive Information Disclosure
Aggregando tutte le sottocategorie "sensitive-information-disclosed" si arriva a ~0.86% del totale. Le combinazioni più comuni sono:

Key (sola): 0.25%
Token: 0.09%
Database: 0.06%
Queste vengono rilevate da _find_hardcoded_secrets_contextual (linea 1192) con analisi di entropia per ridurre i falsi positivi.

Conclusioni Principali
L'ecosistema MCP ha un problema strutturale di sicurezza: quasi 10 vulnerabilità per server in media.
Command injection è il rischio #1: gli sviluppatori MCP tendono a passare input di tool direttamente a comandi di sistema.
La validazione input è quasi assente: 46.370 finding statici indicano che è un antipattern diffuso.
Il gap static/dynamic è informativo: il 80% dei finding "dynamic" sono in realtà analisi statica potenziata (il server non si è avviato), ma il 20% di real fuzzing conferma i problemi.
Node.js domina sia come linguaggio che come superficie di attacco: 24.389 server su 60.205.