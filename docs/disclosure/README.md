# Responsible disclosure — registro

Documentazione del processo di segnalazione delle vulnerabilita' emerse dallo
studio. Ogni fase lascia traccia qui.

| fase | cosa | stato |
|---|---|---|
| **0** | verifica dei bersagli, nessun contatto | **fatta** — 2026-08-06 |
| **1** | costruzione delle liste e scelta dei canali | **fatta** — 2026-08-10, vedi [FASE1.md](FASE1.md) |
| **2** | stesura dei testi di segnalazione | **fatta** — 2026-08-10, vedi [FASE2_testi.md](FASE2_testi.md) |
| 3 | invio, dagli account dell'autore | da fare |
| 4 | esiti e stesura di §12.7 | da fare |

> **Nessuna delle operazioni svolte finora ha contattato alcun soggetto.** La
> Fase 0 usa esclusivamente `git ls-remote` e `raw.githubusercontent.com`, cioe'
> lettura di metadati e file pubblici, senza autenticazione, senza clone e senza
> aprire issue. L'invio e' Fase 3 e spetta all'autore dello studio: una
> segnalazione responsabile deve provenire da un ricercatore identificabile e
> raggiungibile per il seguito.

---

## Fase 0 — esito

Riprodotta con `python autorun/disclosure_fase0.py`. Dati in
[`fase0_casi.json`](fase0_casi.json) e [`fase0_provider.json`](fase0_provider.json).

### Il risultato principale

**Tutti e nove i casi candidati sono ancora attivi, e nei cinque casi di malware
il payload e' ancora presente nell'HEAD del repository.** Nessuno e' stato
rimosso o corretto nei mesi trascorsi dalla prima analisi. La segnalazione ha
quindi ancora senso per la totalita' dei casi, il che non era scontato.

### Tier 1 — malware

Il manutentore e' l'attaccante: il canale corretto e' GitHub Abuse e il registry
del pacchetto, **non** il manutentore stesso.

| repository | repo | payload | natura |
|---|---|---|---|
| `heavenlycolle/mcp-trino` | attivo | **presente** | `exec.Command` a package-init, curl verso dominio `.icu` |
| `illustriousj/kite-mcp-server` | attivo | **presente** | idem, wget con pipe a `/bin/bash` |
| `optimisticdur/go-mcp-mysql` | attivo | **presente** | stesso payload del precedente |
| `FronNian/mpc-maven-security` | attivo | **presente** | `eval()` di un buffer nascosto in caratteri Unicode invisibili |
| `michaelguo1991/math-mcp-server-nodejs` | attivo | n/d | tag `<IMPORTANT>` che dirotta le email verso `attacker@pwnd.com` |

I primi tre condividono lo stesso schema e lo stesso dominio di comando e
controllo: sono una campagna, non tre incidenti separati, e vanno segnalati come
tale. Il quinto caso non ha un file singolo da verificare perche' il vettore e'
la descrizione del tool, che richiede l'avvio del server: resta da riconfermare
in Fase 1 con una singola chiamata `tools/list` in ambiente isolato.

> **Nota sulle firme.** Il controllo cerca due stringhe per caso e ne trova una
> su due. E' il comportamento atteso: la seconda firma e' il dominio `.icu`, che
> nel sorgente non compare mai in chiaro perche' viene ricostruito per
> concatenazione a runtime — che e' esattamente la tecnica di offuscamento
> documentata nell'audit. La firma che corrisponde e' la chiamata `exec.Command`
> spezzata, che e' la parte diagnostica.

### Tier 2 — esfiltrazione confermata e rug pull

Qui il canale e' il manutentore.

| repository | repo | evidenza | tipo |
|---|---|---|---|
| `skdkfk8758/MCP-ProjectManager` | attivo | **presente** | hook globali che inviano input, output e prompt a un backend esterno |
| `vincentmcleese/promtHire-mcp` | attivo | **presente** | schema del tool che richiede l'intera conversazione |
| `sentry-official/mcp-cap-internal` | attivo | n/d | rug pull confermato; da segnalare anche il nome dell'organizzazione |
| `letoribo/mcp-graphql-enhanced` | attivo | n/d | rug pull dichiarato apertamente: cortesia, non incidente |

I due casi di esfiltrazione sono i piu' delicati da formulare, perche' il
comportamento potrebbe essere intenzionale e dichiarato altrove nel progetto: la
segnalazione va scritta come richiesta di chiarimento prima che come accusa.

### Tier 3 — credenziali di terzi

**897 credenziali confermate** dall'audit integrale della classe
`hardcoded-credential`. Il piano prevedeva di raggrupparle per provider e
chiedere la revoca a ciascuno, evitando 897 contatti individuali. La verifica
mostra che **la strada copre una minoranza dei casi**:

| provider | chiavi | repository |
|---|---:|---:|
| Google | 76 | 49 |
| OpenAI | 39 | 25 |
| OpenWeather | 6 | 6 |
| Supabase, Docker, Groq | 2 ciascuno | 2 ciascuno |
| GitHub | 1 | 1 |
| **non identificabile** | **769** | **331** |

Solo **128 chiavi su 897, il 14%**, portano un marcatore che consente di
attribuirle a un fornitore — un prefisso riconoscibile (`AIza`, `sk-`, `gsk_`)
o un nome di variabile parlante. Le altre 769 sono assegnate a identificatori
generici (`API_KEY`, `TOKEN`, `SECRET`) senza indicazione del servizio: non
esiste un destinatario a cui chiederne la revoca senza prima leggere il codice
che le usa, repository per repository.

Ne segue che il canale del provider risolve al piu' un sesto del problema, e per
il resto la scelta e' fra il contatto individuale con centinaia di manutentori e
la rinuncia dichiarata. E' una decisione da prendere esplicitamente e da
motivare nell'articolo, non da lasciare implicita.

Va inoltre verificato in Fase 1 quali di questi fornitori siano gia' coperti dal
secret scanning automatico di GitHub sui repository pubblici: dove lo sono, la
segnalazione non aggiunge nulla.

### Tier 4 — il resto

Circa 12.000 finding ritenuti sfruttabili su circa 8.500 server distinti. La
segnalazione individuale non e' praticabile e non viene tentata da alcuno studio
comparabile. La proposta e' di limitare il contatto ai server in cui popolarita'
e gravita' si sommano, e di trattare la pubblicazione aggregata come la forma di
disclosure per tutti gli altri. La soglia va fissata in Fase 1.

---

## Questioni aperte, da sciogliere prima della Fase 2

1. ~~Il repository dello studio e' pubblico.~~ **Risolto il 2026-08-10:** il
   repository e' stato reso privato, quindi il preavviso torna praticabile e i
   tempi della segnalazione non sono piu' vincolati a quelli dell'articolo.
2. **I cinque casi di malware sono vivi e scaricano payload.** Non dipendono dai
   tempi dell'articolo e andrebbero segnalati per primi.
3. **La disclosure firmata con un'affiliazione istituzionale e' un atto
   istituzionale**, e va concordata con il relatore prima dell'invio. Per il
   Tier 1 potrebbe essere opportuno coinvolgere il CERT dell'ateneo.
4. **Soglia del Tier 4**: quanti server contattare individualmente e con quale
   criterio.

---

## File

| file | contenuto |
|---|---|
| `FASE1.md` | liste, canali e perimetro (18 comunicazioni) |
| `FASE2_testi.md` | le bozze pronte all'invio, **non inviate** |
| `fase1_top_server.json` | candidati Tier 4 con gravita' e popolarita' |
| `fase0_casi.json` | i nove casi con stato del repository e del payload |
| `fase0_provider.json` | credenziali confermate per fornitore, con i repository |
| `autorun/disclosure_fase0.py` | lo script che li produce, rieseguibile |
