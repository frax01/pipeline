## Avvio dei server: allineare real_fuzzing e robustness_fuzzing

Confrontando i due percorsi di fuzzing mi sono accorto che avviavano i server in
modo diverso, ed era proprio questo a far divergere i numeri finali.

Nel real_fuzzing (`_start_mcp_server_process`, UniversalStaticAnalyzer) l'avvio è
asincrono: dopo lo `Popen` aspetto qualche secondo, poi mando un ping JSON-RPC e
resto in ascolto della risposta con un `asyncio.wait_for`. Se il server risponde
è pronto; se il timeout scade ma il processo è ancora vivo lo considero comunque
partito (`return process.poll() is None`).

Nel robustness_fuzzing (`_start_mcp_server`, UniversalDynamicAnalyzer) l'avvio era
invece sincrono e molto più povero: un `time.sleep(2)` e via, con un semplice
`process.poll() is None`. Niente ping, niente test di responsiveness. Il problema
in pratica era questo: un server che ci mette 2-4 secondi a inizializzarsi passava
il check (il processo è vivo), ma quando il robustness cominciava subito a scrivere
i payload su stdin il server non era ancora pronto, le write fallivano o restavano
senza risposta e i payload andavano sprecati.

Ho riscritto `_start_mcp_server` in modo che si comporti esattamente come quello
del real_fuzzing: stesso `Popen`, stessa attesa, ping JSON-RPC e fino a 3 secondi
di ascolto della risposta, e se il processo è ancora vivo lo do per pronto. In
concreto ho sostituito la versione sync con una async (`_start_mcp_server_async`)
identica a `_start_mcp_server_process`, e ora `analyze_server()` la chiama con
`asyncio.run()` come fa già `analyze_server_fuzzing()`. Da quando i due usano lo
stesso identico avvio, i numeri di real_fuzzing e robustness_fuzzing coincidono.

Già che c'ero ho alzato l'attesa iniziale da 2 a 5 secondi in entrambi i metodi.
Il motivo sono i server lanciati con `uvx`: la prima esecuzione scarica il
pacchetto e può sforare i 2 secondi, quindi capitava che il primo analyzer
fallisse e il secondo riuscisse solo perché nel frattempo `uvx` aveva popolato la
cache. Adesso il budget è 5s di sleep + 3s di responsiveness, 8 secondi in totale.

### Server HTTP non più saltati

C'era un buco abbastanza evidente: `UniversalDynamicAnalyzer.analyze_server`
saltava in blocco i server HTTP (loggava "Skipping stdio-based dynamic analysis
for HTTP server", metteva `_server_started = False` e usciva), mentre il
real_fuzzing li gestiva con `_run_http_dynamic_fuzzing`. Ho aggiunto
`_run_http_robustness_fuzzing` così anche il robustness li analizza, allineato al
real.

### Loop a vuoto sul server morto

Dentro `_perform_jsonrpc_fuzzing`, se il server moriva, ogni
`process.stdin.write()` lanciava `BrokenPipeError`, il `continue` passava al
payload successivo e lo stesso errore si ripeteva identico su tutti i payload
rimanenti: il loop continuava a girare su un processo ormai morto. Ora controllo
`process.poll()` prima di ogni payload e tengo un contatore di fallimenti
consecutivi; dopo 3 BrokenPipeError/OSError di fila esco dal loop invece di
insistere.

## Pulizia di processi e pipe

Ogni tanto mi spuntava un `OSError: [Errno 22] Invalid argument` sollevato dal
garbage collector. La causa era che chiudevo i pipe (stdin/stdout/stderr) solo se
il processo era ancora vivo (`process.poll() is None`): se il server moriva durante
il fuzzing i pipe restavano aperti e Python si lamentava quando provava a
chiuderli da solo. Adesso i pipe li chiudo sempre, che il processo sia vivo o morto,
prima di qualsiasi terminate/kill. Vale sia in `_cleanup_scanner_resources` che in
`_stop_mcp_server`.

## Integrazione del comando mcp-guard nella pipeline

`uvx mcp-guard` non funzionava: `mcp-guard` non è pubblicato su PyPI, è un tool
locale in `~/Desktop/Frameworks/mcp-guard/`, quindi `uvx` provava a scaricarlo dal
registry e falliva. In `functions/config.py` (riga 67) ho cambiato il comando da
`[UVX, "mcp-guard", str(CONFIG)]` a `[sys.executable, str(MCP_GUARD_DIR /
"mcp_scanner.py")]`: ora lancio direttamente lo scanner con
`python mcp_scanner.py <url> <repo_path> <command> <elem>`.

In `functions/stats.py` (riga 615) c'era una chiamata a
`update_framework_tests_errors` che però non è mai stata implementata. L'ho tolta:
le altre funzioni di stats (`update_analysis_types`, `update_framework_categories`,
`update_framework_severity`) coprono già tutti i dati che servono.

Sul conteggio: il robustness_fuzzing finisce in `analyses_completed` solo se
`_server_started == True` (in `scan_mcp_server`, intorno alla riga 292). È lo stesso
criterio del real_fuzzing, che conta `real_fuzzing` se il server parte e `dynamic`
se non parte, quindi l'ho lasciato com'era. Tanto adesso che l'avvio è identico i
due valori si allineano da soli.

## Cosa ho cambiato dentro mcp-guard

Lato framework (`C:\Users\francesco\Desktop\Frameworks\mcp-guard\mcp_scanner.py`)
ho messo mano a parecchie cose, in buona parte per farlo girare bene sotto la
pipeline e su Windows.

**Niente più download del repo.** Prima `scan_mcp_server` si scaricava il
repository da GitHub (`download_repository`, `_download_github_repo`,
`_download_github_zip`, `_download_git_repo`). Ho tolto tutta quella parte e
cambiato la firma in `scan_mcp_server(repo_url, repo_path, command, elem,
scan_type="both")`: il path locale e il comando di avvio glieli passa direttamente
la pipeline, così lo scanner lavora sul checkout che ho già su disco invece di
riscaricarlo ogni volta.

**Timeout che non butta via i risultati.** Ho aggiunto
`_run_with_timeout(fn, timeout, name)` che fa girare la fase in un thread e, se
sfora il timeout, restituisce comunque i risultati parziali invece di perdere
tutto. Per farlo funzionare salvo i risultati sull'istanza prima della cleanup,
così se è la cleanup stessa a bloccarsi e a far scattare il timeout i vuln già
trovati non vanno persi.

**Chiusura dei processi robusta su Windows e Linux.** Questo è stato il punto più
rognoso. Su Windows `terminate()` ammazza solo il processo padre, ma i figli (i
worker di node, per dire) restano vivi e tengono aperti i pipe: i thread
dell'executor bloccati su `readline()` non finiscono mai e `asyncio.run()` si
pianta. Adesso uccido l'intero albero dei processi prima di chiudere i pipe; su
Linux ammazzo tutto il process group, altrimenti gli orfani restano attaccati alle
pipe con lo stesso effetto. E come nella pipeline, i pipe li chiudo sempre per non
beccare l'`OSError [Errno 22]`. In cima al file ho aggiunto anche tre cose: ignorare
`SIGPIPE` su Linux (se no il processo muore appena scrive su una pipe il cui lettore
è già crashato), il fix dell'output Unicode su Windows (cp1252 non digerisce le
emoji) e l'override del path di npm, sempre su Windows.

**Via l'analisi statica "finta".** `_perform_enhanced_static_dynamic_analysis` e
`_analyze_server_security_patterns` generavano vulnerabilità inventate: roba
pattern-based spacciata per risultati dinamici. Le ho disabilitate e ho tolto il
fallback che ci ricadeva sopra. Meglio nessun risultato che un risultato
fabbricato. L'analisi statica vera, quella pattern-based con una funzione per ogni
tipo di vulnerabilità, l'ho tenuta e marcata nel codice (trovi i miei commenti
`[francesco]` dal punto in cui comincia).

**Fuzzing basato sui tool veri.** Ho rifatto il cuore del fuzzing dinamico in
`analyze_server_fuzzing`: prima inizializzo il server, poi faccio `tools/list` per
scoprire i tool reali, e per ognuno genero payload mirati, uno per vettore
d'attacco (path traversal, command injection, code injection, SQL injection,
SSRF), iniettandoli nel primo parametro stringa e riempiendo i parametri
obbligatori con default innocui. Provo anche `resources/read` con un path
traversal. A questi aggiungo una batteria di payload a livello di protocollo
(`_generate_protocol_payloads`): versione JSON-RPC sbagliata, campi obbligatori
mancanti, tipi errati, id ai limiti, method vuoto o con caratteri strani, un
payload enorme per provare a esaurire le risorse e un oggetto annidato all'infinito
per cercare uno stack overflow. Durante l'invio controllo se il processo è morto e
in quel caso esco subito. Un payload per vettore, senza duplicati, così evito di
sparare migliaia di richieste inutili.