# Rug pull — le tool description cambiano fra maggio e luglio 2026?

Un **rug pull** e' un server MCP che cambia il proprio comportamento dichiarato
*dopo* essere stato approvato: la descrizione che l'agente legge oggi non e'
quella su cui l'utente aveva dato il consenso. E' la minaccia per cui `mcp-scan`
tiene uno `--storage-file` con l'hash di ogni tool.

---

## 1. Perche' si puo' fare, e perche' non con mcp-scan

`mcp-security-scan` ha un check di rug pull (`X-03`), ma confronta due chiamate
**nella stessa sessione** (T1 vs T2): coglie i server che cambiano subito dopo
l'avvio, non quelli che cambiano nel tempo. Nella rirun ha prodotto 86 finding,
52 tenuti dal filtro e **0 VP**: quasi tutti hanno `before: []`, cioe' sono
server che alla prima chiamata non erano ancora pronti.

`mcp-scan` avrebbe il meccanismo giusto — `W003` = "entita' cambiata rispetto
all'hash memorizzato" — ma **non e' utilizzabile retroattivamente**: non esiste
uno storage file di maggio, e nella rirun i worker ne condividevano uno solo
(e' per questo che gli 837 `W003` sono stati scartati come artefatto). In piu'
memorizza solo hash: direbbe *che* qualcosa e' cambiato, non *cosa*.

**La sorgente che funziona sono i finding gia' archiviati.**
`mcp-security-scan` e `mcp-shield` non leggono il sorgente: avviano il server e
gli chiedono `tools/list`. La descrizione che finisce nel finding e' quindi cio'
che il server dichiarava di se' **nell'istante della scansione** — esattamente
cio' che avrebbe visto un client MCP. Entrambe le analisi l'hanno salvata, a due
mesi di distanza:

| sorgente | dove sta la descrizione |
|---|---|
| `mcp-security-scan` (X-01) | campo `details`: lista JSON completa dei tool del server |
| `mcp-shield` | campi `tool_name` + `tool_description` |

---

## 2. Copertura del confronto

| | |
|---|---:|
| server con inventario dei tool a maggio | 6.945 |
| server con inventario dei tool a luglio | 4.640 |
| **server confrontabili (presenti in entrambe)** | **3.961** |
| coppie (server, tool) confrontate | 16.641 |
| descrizioni **invariate** | 10.937 |
| **descrizioni cambiate** | **393** su 131 server |
| scartati (descrizione vuota da un lato) | 1.052 |

> **Limite da dichiarare.** Nessuna delle due run ha salvato un inventario
> completo: le descrizioni esistono solo dentro i finding, quindi il confronto
> copre i soli server **flaggati in entrambe le passate** — 3.961 su 69.104,
> il **5,7% del dataset**. E' un campione con un bias di selezione evidente
> (si cercano rug pull dove uno scanner aveva gia' segnalato qualcosa), non una
> misura sull'intero ecosistema.

### Due sorgenti, due gradi di completezza

Distinzione che conta per la §6: `mcp-security-scan` salva nel campo `details`
**l'intera lista dei tool** del server, mentre `mcp-shield` registra **solo il
tool che ha segnalato**. Per confrontare le *descrizioni* vanno bene entrambe —
si guarda la stessa coppia (server, tool) nelle due run. Per dire che un tool e'
**nuovo o sparito**, invece, serve l'inventario completo su entrambi i lati:
altrimenti "sparito" significa spesso soltanto "stavolta non e' finito sotto
flag". Su questo insieme misto i tool risultavano 1.029 aggiunti e 3.229 rimossi
— e il fatto che i rimossi fossero il triplo degli aggiunti era il sintomo
dell'artefatto. La §6 usa quindi un sottoinsieme piu' stretto e pulito.

---

## 3. Come sono stati giudicati i 393 cambi

I 393 cambi si distribuiscono su **131 server**, molto disugualmente: un server
solo ne ha 42, dodici server ne hanno almeno cinque, mentre 63 server hanno un
cambio soltanto. Da qui i due filtri.

**Primo taglio — le riscritture di rilascio.** Un server che cambia insieme la
descrizione di cinque o piu' tool sta ridocumentando la propria release, non
modificando di nascosto un tool. Sono **202 cambi**, marcati `REL` e non
esaminati uno per uno. Un rug pull, per definizione, e' mirato: interessa un
tool, non l'intero catalogo.

**Secondo taglio — dove puo' esserci una capability nuova.** Sui restanti 191
cambi si applicano due euristiche:

- **capability comparsa**: una classe di verbi presente nella descrizione di
  luglio e assente in quella di maggio (scrittura, cancellazione, esecuzione,
  rete, credenziali, filesystem, privilegi);
- **linguaggio direttivo comparso**: frasi tipiche del prompt-injection nascosto
  (`ignore previous`, `do not tell the user`, `<IMPORTANT>`, `you must`...).

Restano **48 candidati**, che sono stati **letti a mano uno per uno**,
confrontando le due descrizioni per intero. Gli altri 143 sono riformulazioni
senza alcun segnale.

> Le euristiche sono volutamente sbilanciate verso il **recall**: segnalano 48
> casi di cui solo 3 reggono alla lettura. Meglio leggerne 45 di troppo che
> perderne uno. Il grosso dei falsi positivi viene da descrizioni che si
> allungano: `Execute command with sudo` → una spiegazione di cinque righe della
> *stessa* operazione fa comparire parole di sei classi diverse.

## 4. Esito

| verdetto | cambi | significato |
|---|---:|---|
| **RP-C** | **1** | il tool puo' fare oggi qualcosa di pericoloso che prima non poteva |
| **RP-D** | **2** | capability nuova ma di portata limitata, o gia' implicita prima |
| DOC | 188 | stessa capability, descrizione piu' accurata |
| REL | 202 | il server ha ridocumentato in blocco tutti i suoi tool (rilascio) |

**Nessun rug pull malevolo.** Zero istruzioni nascoste, zero direttive di
esfiltrazione, zero tentativi di dirottare altri tool. Il segnale piu' vicino a
un attacco — linguaggio direttivo comparso nella descrizione — ha prodotto 3
casi, tutti legittimi alla lettura (guida al workflow del server stesso, del
tipo "per le transazioni standard usa prima `zetrix_sdk_*`").

### L'unico caso confermato

**`letoribo/mcp-graphql-enhanced` → `query-graphql`**

| | |
|---|---|
| maggio | `Execute a GraphQL query against the endpoint` |
| luglio | `Execute GraphQL operations (queries and mutations) against the federated system. WARNING: This tool performs remote operations. 'Mutation' operations will modify persistent state; execute these only when a state change is intended.` |

Il tool passa da **sola lettura a lettura-scrittura**. Un agente che a maggio
aveva approvato "esegui una query" a luglio esegue mutation che modificano stato
persistente. E' la forma esatta del rug pull — con l'attenuante che il cambio e'
dichiarato apertamente, `WARNING` compreso.

### I due casi deboli

- **`piotr-agier/google-drive-mcp` → `deleteRange`**: a maggio *"Delete content
  between start and end indices **in a Google Doc**"*, a luglio *"Works on Google
  Docs **and text/\* files**"*. Non e' una capability nuova ma l'allargamento del
  raggio d'azione di una gia' distruttiva.
- **`platano78/smart-ai-bridge` → `spawn_subagent`**: a luglio compare
  *"⚠️ DESTRUCTIVE when `write_files:true`: code blocks the agent emits are saved
  into `work_directory`"*, assente a maggio — ma con default `false` e avviso
  esplicito.

> **Un caso ritirato.** `littlebearapps/outlook-mcp` → `manage-contact` era stato
> classificato RP-D perche' a luglio dichiara *"Full CRUD (destructive: covers
> `delete` action)"*. Rileggendo la descrizione **integrale** di maggio, pero',
> `action=update` e `action=delete` erano gia' elencate: nessuna capability
> nuova, solo l'etichetta "destructive" spostata in testa. Il verdetto e' stato
> corretto in `DOC`. E' il rischio tipico di questo confronto: **le descrizioni
> vanno lette per intero**, perche' l'elenco delle azioni sta spesso in fondo.

---

## 5. Come leggere il risultato

**Tutti e tre i cambi vanno nella direzione opposta al rug pull.** In ogni
caso la capability nuova e' *dichiarata piu' forte*, non nascosta: `WARNING`,
`destructive`, `⚠️ DESTRUCTIVE`. Un rug pull vero fa il contrario — amplia
silenziosamente cio' che il tool puo' fare, lasciando innocua la descrizione.

Il risultato e' quindi **negativo, e il negativo e' il dato**: la minaccia che
giustifica l'intera meccanica di hashing di `mcp-scan` non si osserva in questa
finestra e su questo campione. Cio' che si osserva e' un ecosistema che
**migliora la propria documentazione**: 188 riformulazioni piu' accurate e 202
ridocumentazioni di rilascio, contro 3 espansioni di capability.

Due cautele prima di generalizzare:

1. **La finestra e' di due mesi.** Un rug pull puo' avvenire su tempi piu'
   lunghi, o essere gia' avvenuto prima di maggio.
2. **Il campione e' il 5,7% del dataset e non e' casuale.** Copre solo i server
   che uno scanner aveva flaggato in entrambe le passate.

Per una misura sull'intero ecosistema serve la **git history dei repository**:
per i 60.205 server GitHub il "prima" non va conservato, ce l'hanno i repo
stessi, e la history fornisce anche la **data** di ogni modifica. E' l'estensione
naturale di questo lavoro.

---

## 6. I tool **aggiunti**: perche' NON si possono misurare

Cambiare una descrizione non e' l'unico modo di fare un rug pull, e nemmeno il
piu' comodo. In MCP il consenso si da' **per server**: se approvi un server con i
tool A, B, C e due mesi dopo espone anche D, nessuno ti richiede una nuova
approvazione. Aggiungere un tool e' piu' facile e meno visibile che riscriverne
uno, ed e' il vettore che conterebbe di piu'.

**Con questi dati non e' misurabile, e una versione precedente di questo
documento sbagliava nel sostenere il contrario.**

Il motivo: per dire che un tool e' *nuovo* serve l'inventario **completo** del
server a maggio. Si era assunto che il campo `details` dei finding di
`mcp-security-scan` lo contenesse. **Non e' cosi'**: `details` contiene solo i
tool che hanno fatto scattare quello specifico finding. Verifica diretta:

| server | tool in `details` a maggio | tool realmente esposti oggi |
|---|---:|---:|
| `0xDmsk/pwndoc-mcp` | 1 (X-01) + 2 (X-02) | **47** |
| `0xanmol/dynamic-mcp-server` | 1 (X-01) + 2 (X-02) | 7 |

I "357 tool aggiunti su 2.515 server" calcolati su quell'assunto sono quindi in
larghissima parte tool che **a maggio esistevano gia' e non erano stati
segnalati**. Il caso allora indicato come piu' rilevante — `paolino/mcp-memory-server`
che acquisisce `kill_processes` — non e' dimostrabile: quel tool poteva esserci
gia'. Lo script `autorun/rugpull_nuovi.py` resta nel repo con il suo avviso di
invalidita', a documentazione dell'errore.

### L'asimmetria che resta utilizzabile

Il ri-listing (`autorun/relist_run.py`) interroga `tools/list` e ottiene l'elenco
**completo** di oggi. Da qui:

- **tool spariti: misurabili.** Un tool presente a maggio e assente dalla lista
  completa di oggi e' davvero stato rimosso.
- **tool aggiunti: non misurabili**, ne' ora ne' mai su questa finestra: la
  baseline completa di maggio non esiste e non e' ricostruibile.

L'inventario prodotto dal ri-listing e' pero' la **prima baseline completa
reale** dell'ecosistema: per qualunque confronto futuro il problema non si
ripresenta.

---

## 7. Riprodurre

```bash
python autorun/rugpull_diff.py --json autorun/rugpull_cambi.json
python autorun/rugpull_verdetti.py --out autorun/rugpull_verdetti.json
python autorun/rugpull_nuovi.py --json autorun/rugpull_nuovi.json
```

| file | contenuto |
|---|---|
| `autorun/rugpull_diff.py` | estrazione degli inventari e diff fra le due run |
| `autorun/rugpull_cambi.json` | i 393 cambi, con prima/dopo integrali |
| `autorun/rugpull_verdetti.py` | criteri e verdetti manuali |
| `autorun/rugpull_verdetti.json` | i 393 verdetti |
| `autorun/rugpull_nuovi.py` | i tool **aggiunti**, sul sottoinsieme a inventario completo |
| `autorun/rugpull_nuovi.json` | i 357 tool nuovi, con verdetto |
