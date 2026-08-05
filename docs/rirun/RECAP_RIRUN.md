# RECAP DELLA RIRUN — confronto con l'analisi di maggio

Documento di sintesi della **seconda esecuzione completa** dell'analisi di
sicurezza dei server MCP (luglio 2026), messa a confronto con la prima
(maggio 2026, archiviata in `pipeline_DATI_BACKUP`).

Tutti i numeri qui sono verificati sui file, non ripresi da documenti precedenti.
Gli script che li producono sono in `autorun/` (`aggregato_finale.py`,
`compare_vp.py`, `analisi_concordanza.py`).

---

## 1. Il funnel

| | maggio | luglio |
|---|---:|---:|
| server analizzati | 69.104 | 69.104 |
| framework eseguiti | 7 | **6** (mcp-scan non piu' eseguibile, dati importati) |
| findings grezzi | 3.917.093 | **3.531.813** |
| dopo **Stage 1** (filtri regex) | 73.594 | **56.908** |
| dopo **Stage 2A** (regole HC) | 22.997 | 19.849 ⚠ |
| **Stage 2B** (LLM sugli incerti) | 5.800 → 565 | **6.039 → 668** |
| mcp-scan (motore proprio) | 4.396 | 4.396 *(importati da maggio)* |
| **VP finali** | **27.958** | **24.225** |

> I valori di **luglio sono deduplicati**, quelli di **maggio sono gli originali**,
> non ritoccati. Il perche' e il come stanno tutti in **§2**.
>
> ⚠ L'unica riga ancora non deduplicata e' *dopo Stage 2A*: non e' stato possibile
> risalire ai file da cui era stata ricavata, quindi non si sa quanto vi
> contribuisse watch. Va rifatta o tolta.

> La tabella delle 17 categorie (§4) totalizza **24.221**: i 4 VP di differenza
> sono `watch/steganographic-attack`, categoria che nella prima analisi valeva 0
> VP e che quindi non ha una casella fra le 17.

Lo Stage 2B ha cambiato classificatore: **llama3 → Claude Sonnet**. Su un numero
simile di incerti (5.800 vs 6.039) promuove 668 VP invece di 565 — cioe' il
**2,8% dei VP finali**: il grosso del risultato viene dalle regole HC,
deterministiche e identiche nelle due run. Il `6.039 → 668` esclude i 1.337
incerti di scan, importati da maggio e non riclassificati.

> **Nota sui 3,1 M della vecchia slide**: il totale reale di maggio e' 3.917.093.
> I 3,1 M erano un sottoinsieme (probabilmente solo cio' che entrava nello
> Stage 1). Il numero va corretto se si riusa quella slide.

---

## 2. Da quali scanner vengono i findings

Maggio: valori originali. Luglio: **deduplicati** (spiegazione qui sotto).

| scanner | maggio | luglio | Δ |
|---|---:|---:|---:|
| **mcp-watch** | **3.693.688** (94%) | **3.324.593** (94%) | −10% |
| mcp-guard | 93.813 | 105.742 | +13% |
| mcp-check | 96.140 | 84.537 | −12% |
| mcp-security-scan | 12.737 | 6.396 | −50% |
| mcp-scan | 9.986 | **837** | **−92%** |
| mcp-shield | 6.191 | 6.249 | +1% |
| fuzzing | 4.538 | 3.459 | −24% |
| **totale** | **3.917.093** | **3.531.813** | −10% |

Il volume e' dominato da **mcp-watch** in entrambe le passate (94%). Negli altri
sei tool i duplicati sono ~0%, quindi per loro righe e distinti coincidono.

### La deduplicazione — l'unico posto dove la spiego

I 36 worker della seconda tranche di watch sono stati riavviati molte volte su
intervalli sovrapposti (riassegnazione dei chunk), e `autorun/merge6.py`
concatena i 50 shard **senza deduplicare**. Contando per contenuto del finding:

| | righe | distinti | duplicati |
|---|---:|---:|---:|
| watch, luglio | 5.678.632 | **3.324.593** | **41,5%** |
| watch, maggio | 2.441.879 | 2.437.792 | 0,2% |

E' un problema **esclusivo di watch nella rirun**: gli altri sei tool e l'intera
prima analisi hanno ~0% di duplicati. Per questo i valori di maggio non sono
stati ritoccati, mentre tutti i valori di luglio in questo documento sono
deduplicati. La correzione e' applicata in `aggregato_finale.py` e
`compare_vp.py`; **manca ancora in `merge6.py`**, quindi rilanciando l'analisi il
problema si ripresenta.

Effetti a valle: watch VP 2.011 → **1.224**, FP 12.242 → **6.801**,
credential-leak 1.176 → **652**; totale rirun 25.012 → **24.225**.

> **Una cautela sul confronto di watch qui sopra.** Il valore di maggio
> (3.693.688) comprende `toxic-flow` (1.229.886) e `server-spoofing` (21.923),
> che a luglio non sono state scaricate perche' **nessuno stage le elabora** —
> ne' `stage1_filter.py`, ne' `stage1_filter_remaining.py`, ne'
> `stage2_pipeline.py`. Il −10% mette quindi a confronto insiemi di categorie
> diversi. Sulle stesse nove categorie il confronto e' **2.437.792 → 3.324.593,
> cioe' +36%**.

### Da cosa viene davvero l'aumento

A categorie omogenee e senza duplicati:

| | maggio | luglio | rapporto |
|---|---:|---:|---:|
| findings watch distinti, categorie elaborate | 2.437.792 | 3.324.593 | **×1,36** |
| server che hanno prodotto almeno un finding | 34.359 | 34.005 | ×0,99 |
| **findings per server** | **70,9** | **97,8** | **×1,38** |

**Attenzione: la crescita del dataset non spiega l'aumento.** I server che
producono findings sono gli stessi (−1%), quindi gli 8.899 npx aggiunti non hanno
allargato la base. L'incremento e' **tutto densita'**: lo stesso server produce
il 38% di findings in piu' rispetto a maggio.

Le due ipotesi da verificare — **non ancora misurate** — sono che i repository
siano cresciuti in due mesi (piu' codice, piu' match) e che i server npx, il cui
sorgente viene ottenuto con `npm pack`, contengano bundle e file minificati che
producono un numero sproporzionato di match. La seconda si testa separando la
densita' dei server GitHub da quella degli npx.

### I server sono cambiati?

**No.** Sono sostanzialmente gli stessi:

| | |
|---|---:|
| server con almeno un finding di watch, maggio | 34.359 |
| server con almeno un finding di watch, luglio | 34.005 |
| **in comune** | **32.752 (95%)** |
| solo maggio | 1.607 |
| solo luglio | 1.253 |

Il +50% che si leggeva sui dati grezzi **non viene da server nuovi**: per la
maggior parte era duplicazione, il resto e' l'aumento di densita' qui sopra.

---

## 3. La validazione manuale

| | maggio | luglio |
|---|---:|---:|
| finding ispezionati a mano | 1.579 | **1.590** |
| precisione pesata | **64,8%** | **49,7%** |
| VP realmente sfruttabili | ~18.111 | **~12.042** |

Criterio: **confermato = VP-C + VP-D** (sfruttabile, anche con impatto limitato).
I **VP-L** (capability dichiarata dal server, non sfruttabile da sola) contano
come non confermati, come nella prima analisi.

---

## 4. Le 17 categorie

| categoria | VP mag | % mag | VP lug | % lug | Δ |
|---|---:|---:|---:|---:|---:|
| Protocol violation | 15.436 | 60% | 10.900 | **63%** | +3 |
| Dangerous capabilities | 3.745 | 67% | 3.294 | 28% | −39 |
| SQL injection | 2.406 | 53% | 2.638 | 7% | −47 |
| Sensitive info disclosure | 1.873 | 100% | 2.224 | 42% | −58 |
| Credential leak | 1.342 | 94% | 1.601 | 72% | −22 |
| Untrusted content | 952 | 100% | 952 | **93%** | −7 |
| SSRF | 741 | 53% | 896 | 33% | −20 |
| Path traversal | 537 | 33% | 687 | **56%** | **+23** |
| Command injection | 274 | 27% | 371 | **68%** | **+41** |
| Code injection | 220 | 43% | 257 | 19% | −24 |
| Input validation | 254 | 42% | 171 | 20% | −22 |
| Prompt injection | 118 | 81% | 129 | 54% | −27 |
| Insecure deserialization | 31 | 93% | 83 | 40% | −53 |
| Access control | 8 | 25% | 9 | 29% | +4 |
| Sensitive file access | 18 | 39% | 5 | 0% | −39 |
| Data exfiltration | 2 | 100% | 2 | 100% | 0 |
| Tool shadowing | 1 | 100% | 2 | 50% | −50 |
| **TOTALE** | **27.958** | **64,8%** | **24.221** | **49,7%** | **−15,1** |

Le 17 categorie sono **identiche** fra le due analisi: ognuna aggrega piu'
sotto-categorie di tool diversi, e la mappatura e' stata ricostruita verificando
che la somma riproduca esattamente i totali di maggio (27.958, riga per riga).

---

## 5. I punti da portare

**1. La pipeline e' stabile.** Stessi server (95% di sovrapposizione), stessi
filtri, volumi confrontabili. Dove il criterio e' oggettivo le due analisi
coincidono: protocol violation 60% vs 63%, untrusted content 100% vs 93%,
segreti hardcoded 94% vs 95%.

**2. Il calo di precisione e' di criterio, non di dato.** Concentrato in quattro
categorie, tutte con la stessa causa: cosa conti come "sfruttabile" quando il
pattern e' reale ma la capability e' dichiarata o l'input non e' controllabile.
Il caso piu' netto e' `credential-leak`, dove `token.write(creds.to_json())` —
il token OAuth dell'utente salvato nella sua cache locale seguendo la
documentazione ufficiale di Google — vale **54,9% dei finding a maggio (365/665)
e 53,2% a luglio (347/652 distinti)**: la stessa proporzione in entrambe le
passate. Contandolo FP la categoria sta al 38%, contandolo VP oltre il 90%.

**3. mcp-scan non e' piu' eseguibile.** L'endpoint gratuito
`mcp.invariantlabs.ai` non ha piu' record DNS; la CLI di `mcp-scan 0.4.2`
ripiega su `api.snyk.io`, che risponde `{"detail":"Push key is required"}` →
110.658 fallimenti nei log, e ogni tool torna `safe`. E' un limite dello stato
dell'arte, non della pipeline: uno scanner che delega l'analisi a un backend
proprietario smette di funzionare quando quel backend sparisce.

**4. Le categorie aggregate nascondono differenze enormi.**
`Dangerous capabilities` unisce sotto-categorie che confermano allo 0%, 7%, 20%
e 80%. Il numero della categoria dipende da quale strumento ha prodotto piu'
finding: il campione va stratificato e pesato, non preso da una sola fonte.

**5. Il toxic flow completo e' raro.** Su 1.411 server con capability pericolose,
solo **30 (2,1%)** presentano anche una sorgente di contenuto non fidato sullo
stesso server. Il rischio reale nasce dalla composizione multi-server, che
nessuno dei sette strumenti analizzati e' in grado di rilevare.

---

## 6. Problemi noti e limiti

- **Duplicazione in watch** (spiegata in §2): tutti i valori di luglio in questo
  documento sono deduplicati, quelli di maggio sono gli originali. `merge6.py`
  non deduplica ancora.
- **Campione non casuale**: la validazione manuale segue l'ordine alfabetico dei
  server (come a maggio). Le percentuali descrivono il campione, non sono stime
  estrapolabili con intervallo di confidenza.
- **mcp-scan importato**: i 4.396 VP di scan vengono da maggio, quindi per quella
  categoria il confronto e' a delta zero per costruzione.
- **`security_scan` −50%**: calo non ancora investigato, su un tool che nella
  rirun ha girato regolarmente al 100%.
- **Densita' +38% per server in watch**: a parita' di server (34.359 → 34.005) e
  senza duplicati, ogni server produce il 38% di findings in piu'. Le due cause
  candidate (repository cresciuti in due mesi; bundle/minificati dei server npx
  ottenuti via `npm pack`) **non sono ancora state separate**. E' l'ultima parte
  del +50% grezzo che resta senza spiegazione misurata.

---

## 7. Dove sono i dati

| cosa | dove |
|---|---|
| risultati per tool | `<tool>/postprocessing/**/vp.json`, `fp.json`, `audit.json` |
| dati grezzi scaricati | `pipeline_rerun_pull/` |
| validazione manuale | [`MANUAL_RIRUN.md`](MANUAL_RIRUN.md), verdetti in `autorun/manual_audit/` |
| audit integrale credenziali | `autorun/credleak_audit/` |
| confronto VP | [`CONFRONTO_FINALE.md`](CONFRONTO_FINALE.md), [`CONFRONTO_RIRUN.md`](CONFRONTO_RIRUN.md) |
| analisi del consenso | [`CONCORDANZA.md`](CONCORDANZA.md) |
| funnel di watch | [`WATCH_FUNNEL.md`](WATCH_FUNNEL.md) |
| rug pull | [`RUGPULL.md`](RUGPULL.md), dati in `autorun/rugpull_*.json` |
| prima analisi | `pipeline_DATI_BACKUP/analysisAllData/` |
