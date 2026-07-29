# Stage 2B — criteri di classificazione VP / FP

Sostituisce il classificatore `llama3` della tesi. Ogni record è un **cluster**:
finding con evidenza equivalente, che quindi ricevono lo stesso verdetto.

## Regola generale

Decidere **VP** (vero positivo) solo se la vulnerabilità è **reale e
raggiungibile da un attaccante** attraverso il server MCP. Altrimenti **FP**.

> **In caso di dubbio → FP.** La pipeline è dichiaratamente conservativa verso il
> falso positivo: meglio pochi VP solidi (che passeranno la validazione manuale)
> che molti VP rumorosi. Non marcare VP "per sicurezza".

Non serve giudicare la gravità: solo se è reale.

## FP quasi sempre (indipendentemente dalla categoria)

- **File di test, esempi, fixture, documentazione**: percorsi che contengono
  `test/`, `tests/`, `spec/`, `__tests__/`, `example/`, `demo/`, `fixtures/`,
  `docs/`, `sample`, o nomi `test_*.py`, `*.test.ts`, `conftest.py`.
- **Dipendenze di terzi**: `node_modules/`, `vendor/`, `site-packages/`,
  `dist/` e `build/` quando sono codice compilato/minificato di libreria.
- **Placeholder e valori fittizi**: `your-api-key`, `xxx`, `changeme`,
  `<token>`, `example.com`, `sk-000...`, stringhe palesemente inventate.
- **Codice commentato** o stringhe di documentazione.
- **Input non controllato dall'attaccante**: valore che viene da una costante,
  da configurazione locale dell'operatore o da un percorso hardcoded.

## Per categoria

### `hardcoded-credential-static`
- **VP**: segreto dall'aspetto reale in codice di produzione (chiave con
  prefisso e entropia: `ghp_`, `sk-`, `AKIA`, `xoxb-`, JWT, chiave privata PEM).
- **FP**: placeholder, variabile letta da env (`os.getenv`, `process.env`),
  segreto in file di test, valore vuoto, nome di variabile senza valore.

### `path-traversal-static` / `-fuzzing`
- **VP**: un input dell'utente/tool finisce in un percorso file **senza**
  normalizzazione o controllo di contenimento; nel fuzzing, la risposta mostra
  contenuto realmente fuori dalla directory prevista (es. `/etc/passwd`, SAM).
- **FP**: percorso costruito da costanti o da directory base fissa; presenza di
  `path.resolve` + controllo `startsWith(base)`; risposta che è solo un errore.

### `command-injection` / `code-injection` (static e fuzzing)
- **VP**: concatenazione di input non sanitizzato in `exec`/`eval`/`system`, o
  risposta del fuzzing che dimostra esecuzione avvenuta (output del comando).
- **FP**: argomenti passati come array (`execFile(cmd, [args])`), input da
  enum/valori fissi, `eval` su dato interno, risposta che è solo un eco.

### `sql-injection-static`
- **VP**: query costruita per concatenazione/f-string con input esterno.
- **FP**: query parametrizzata (`?`, `$1`, `:name`), ORM, DDL statico.

### `ssrf-static`
- **VP**: URL di una richiesta HTTP costruito con input dell'utente senza
  allowlist di host.
- **FP**: URL su dominio fisso/costante, o base URL da configurazione.

### `sensitive-info-disclosed-fuzzing` / `information-disclosure-fuzzing`
- **VP**: la **risposta** contiene un segreto reale o dati interni (chiave API
  valorizzata, contenuto di `/etc/passwd`, variabili d'ambiente, path assoluti
  del sorgente in stack trace).
- **FP**: la risposta contiene solo il **nome** del parametro (`api_key=`) senza
  valore, testo di documentazione, eco del payload, descrizione del tool,
  messaggio d'errore generico.

### `dangerous-tool-handler-static` / `dangerous-capabilities` (security_scan)
- **VP**: il tool espone davvero un'operazione distruttiva o di esecuzione
  arbitraria comandata da input libero (`execute_command(cmd)`, `write_file`
  con percorso libero, `delete_*` senza vincoli).
- **FP**: capacità dichiarata ma vincolata da schema chiuso (enum, insieme fisso
  di operazioni), oppure il tool è di sola lettura, oppure "pericoloso" solo per
  il nome (es. `run_query` su un dataset in sola lettura).

### `prompt-injection-static` / `hidden-instructions` (shield)
- **VP**: la descrizione del tool contiene istruzioni rivolte al modello per
  alterarne il comportamento o nasconderle all'utente (`<IMPORTANT>`, "ignore
  previous instructions", "do not tell the user", testo nascosto/offuscato).
- **FP**: normale documentazione d'uso, anche se contiene "important" in senso
  discorsivo; indicazioni d'ordine legittime ("call X before Y") che servono al
  funzionamento e non nascondono nulla.

### `insecure-deserialization-static`
- **VP**: `pickle.loads` / `yaml.load` senza `SafeLoader` su dato esterno.
- **FP**: deserializzazione di dato prodotto internamente o di file di config
  locale; `yaml.safe_load`.

### categorie `protocol-*` (guard) e `check` (conformance)
Sono **problemi di conformità**, non exploit.
- **VP**: solo se la deviazione ha un impatto di sicurezza concreto (il server
  accetta messaggi non autenticati che non dovrebbe, oppure espone dettagli
  interni).
- **FP**: errore di validazione corretto, argomenti invalidi rifiutati,
  autenticazione richiesta (è il comportamento giusto), errore di rete/API
  esterna (`status 5xx`, timeout), metodo MCP non implementato.

## Formato di output

Un file JSON per batch, in `autorun/stage2b/verdicts/verdict_NNN.json`:

```json
{
 "batch": 7,
 "verdetti": [
  {"id": "3632a408fce1", "verdetto": "FP", "motivo": "errore di validazione argomenti: comportamento corretto"},
  {"id": "9ab1c2d3e4f5", "verdetto": "VP", "motivo": "token ghp_ reale in codice di produzione"}
 ]
}
```

- `id` = campo `id` del cluster, copiato **esatto**.
- `verdetto` = `VP` o `FP` (nessun altro valore).
- `motivo` = una riga, in italiano, concreta (cosa nell'evidenza decide).
- **Ogni cluster del batch deve comparire esattamente una volta.**
