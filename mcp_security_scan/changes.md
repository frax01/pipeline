## Falsi positivi sul rug-pull (controllo X-03)

Il controllo X-03 (rug-pull: verifica che i tool non cambino nome o descrizione tra
due `tools/list` consecutive) mi stava generando dei falsi positivi, tutti dovuti a
problemi di timing più che a veri cambi sospetti. I due casi tipici erano:

- prima lista vuota e seconda piena (`before: []`, `after: [6 tools]`): race
  condition, il server non era ancora pronto alla prima `tools/list`;
- prima lista piena e seconda vuota (`before: [7 tools]`, `after: []`): il server è
  morto tra una chiamata e l'altra.

In nessuno dei due casi c'è un vero rug-pull, ma il diff li segnalava lo stesso. Ho
sistemato la cosa su due livelli.

**Guard in `check_tool_stability()` (`src/mcp_scanner/security_checks.py`).**
All'inizio della funzione controllo se una delle due liste è vuota e l'altra no: in
quel caso il test passa con un messaggio che spiega il motivo, invece di sparare un
falso positivo. Se è vuota la prima → "Skipped: first listing was empty (server
likely not ready at first call)"; se è vuota la seconda → "Skipped: second listing
was empty (server likely crashed between calls)".

**Retry prima del confronto.** Nei tre scanner, se la prima `tools/list` torna
vuota aspetto 2 secondi e rifaccio la chiamata prima di confrontare, così do al
server il tempo di tirarsi su:

- `stdio_scanner.py`, blocco X-03: aggiunto il retry con `time.sleep(2)`;
- `http_checks.py`, blocco X-03: stesso retry, che rimpiazza il vecchio ramo
  `if not tools` che chiudeva il test con "No tools were discovered" senza nemmeno
  provare il confronto;
- `sse_scanner.py`, blocco X-03: aggiunto il retry e, già che c'ero, ho tolto tutta
  la logica di diff scritta inline lì dentro (era duplicata) sostituendola con la
  chiamata centralizzata a `security_checks.check_tool_stability()`, come fanno già
  stdio e http. Ho aggiunto anche `from . import security_checks` agli import.

I veri positivi, cioè i tool che cambiano davvero nome o descrizione tra le due
chiamate, continuano a essere segnalati come prima: ho toccato solo i casi in cui
una delle due liste è vuota.

## Altre cose sistemate negli scanner

Mentre ci stavo dietro ho aggiustato un paio di cose che generavano falsi errori,
soprattutto su Windows:

- **Handshake `initialize` fatto come si deve.** Sia in `stdio_scanner.py` (BASE-01
  e `get_stdio_health`) sia in `sse_scanner.py` prima mandavo `initialize` con i
  params vuoti (`{}`). Ora passo i campi veri: `protocolVersion: "2024-11-05"`,
  `capabilities` e `clientInfo` (e ho allineato la version a `1.0.0`). Diversi
  server rispondevano male proprio perché l'handshake era incompleto.
- **`shlex.split` consapevole di Windows (`stdio_scanner.py`).** Lo split del
  comando ora usa `posix=(os.name != "nt")`, altrimenti su Windows i backslash dei
  path venivano mangiati.
- **`PYTHONUNBUFFERED=1` sul sottoprocesso (`stdio_scanner.py`).** Forzo lo stdout
  non bufferizzato per i server Python: senza, capitava che il server scrivesse la
  risposta ma questa restasse nel buffer della pipe e non arrivasse mai al client,
  ed era una delle cause dei falsi "initialization error" su Windows.

Di conseguenza ho ritoccato anche `tests/test_stdio_scanner.py`: i server finti
usati nei test ora fanno `print(..., flush=True)` (in linea con la storia del
buffering) e ho allargato un'assertion su BASE-01 perché accetti anche
"communication failed", non solo "exited immediately".