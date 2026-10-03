# Fase 2 — testi di segnalazione

Bozze pronte all'invio. **Nessuna di queste comunicazioni e' stata inviata**:
l'invio e' Fase 3.

Tutti i testi sono nel formato concordato con il relatore: identita' completa
dichiarata in apertura, registro formale, nessuna richiesta e nessuna scadenza,
e in chiusura i recapiti dei tre ricercatori. L'unico segnaposto rimasto e'
`[DATA]`, la data in cui si verifica che il caso sia ancora presente, che va
messa il giorno dell'invio e non prima.

I 455 messaggi della campagna credenziali sono generati automaticamente nello
stesso formato in [`messaggi/`](messaggi/); si rigenerano con
`python autorun/disclosure_credenziali.py --solo-testi`.

Due regole che valgono per tutti: **non promettere una data di pubblicazione**
che non si e' certi di rispettare, e **non allegare mai credenziali in chiaro**
nel corpo di un messaggio.

**Blocco di chiusura standard**, identico in ogni testo salvo dove indicato:

> Should you require any further information or clarification regarding the
> study, the methodology, or this disclosure, please feel free to contact any of
> the researchers involved:
>
> * Francesco Martignoni — Former Master's Student, Politecnico di Milano —
>   francesco.martignoni@mail.polimi.it
> * Michele Carminati — Associate Professor, Politecnico di Milano, DEIB —
>   michele.carminati@polimi.it
> * Stefano Longari — Assistant Professor, Politecnico di Milano, DEIB —
>   stefano.longari@polimi.it
>
> Kind regards,
> Francesco Martignoni
> Politecnico di Milano
> francesco.martignoni@mail.polimi.it

Nel seguito il blocco e' abbreviato in **[CHIUSURA]**.

---

## 1. GitHub Abuse — i tre trojan correlati

Da inviare come **unica segnalazione** su
`https://github.com/contact/report-abuse`, categoria *malware or exploits*.
Presentarli insieme e' piu' efficace: condividono schema di offuscamento e
infrastruttura, e la correlazione e' essa stessa una prova.

> **Subject:** Responsible disclosure: coordinated malware campaign across three MCP server repositories
>
> Dear GitHub Trust & Safety team,
>
> My name is Francesco Martignoni. I am a former Master's student at Politecnico
> di Milano, where, as part of my thesis project, I conducted a large-scale
> analysis of the Model Context Protocol (MCP) ecosystem, with a particular
> focus on identifying potential security vulnerabilities and misconfigurations
> in publicly available MCP servers.
>
> As part of this research, we analysed 69,104 publicly published MCP servers.
> Three of those repositories execute a remote payload at load time. We believe
> they form part of a single coordinated campaign rather than three independent
> incidents, and we are therefore reporting them together.
>
> **Repositories**
>
> 1. `https://github.com/heavenlycolle/mcp-trino` — `cmd/server/main.go`, line 195
> 2. `https://github.com/illustriousj/kite-mcp-server` — `kc/api.go`, line 25
> 3. `https://github.com/optimisticdur/go-mcp-mysql` — `main.go`, line 477
>
> **Observed behaviour**
>
> In each repository, a package-level variable initialiser invokes
> `exec.Command` with a shell interpreter whose path is assembled through string
> concatenation (for example `"/bi" + "n/s" + "h"`), passing a command that is
> likewise reconstructed at runtime from an array of string fragments. The
> reconstructed command downloads a binary from a `.icu` domain and executes it.
>
> Two properties appear to us to remove any ambiguity as to intent. First, the
> code runs at package initialisation, so no exported function needs to be
> called: merely importing or building the module is sufficient to trigger it.
> Second, the string splitting serves no functional purpose and has the sole
> effect of defeating a search for the literal command or hostname in the
> source.
>
> All three repositories present themselves as legitimate MCP connectors, for
> Trino, Kite and MySQL respectively, and are indexed as such in public MCP
> registries, which is how they entered our dataset. The three share the same
> obfuscation technique and resolve to the same command-and-control
> infrastructure.
>
> We verified on [DATA] that the code is still present in the current default
> branch of all three repositories.
>
> We have not executed the payload outside a controlled and isolated
> environment, and we have not interacted with the remote infrastructure in any
> way. The full technical analysis is available on request.
>
> [CHIUSURA]

---

## 2. GitHub Abuse — backdoor steganografica

> **Subject:** Responsible disclosure: obfuscated backdoor in MCP server repository (mpc-maven-security)
>
> Dear GitHub Trust & Safety team,
>
> My name is Francesco Martignoni. I am a former Master's student at Politecnico
> di Milano, where, as part of my thesis project, I conducted a large-scale
> analysis of the Model Context Protocol (MCP) ecosystem, with a particular
> focus on identifying potential security vulnerabilities and misconfigurations
> in publicly available MCP servers.
>
> As part of this research, we analysed 69,104 publicly published MCP servers.
> I am writing to report one of them.
>
> **Repository:** `https://github.com/FronNian/mpc-maven-security` —
> `src/index.ts`, line 19
>
> The file contains a legitimate MCP entry point of seventeen lines, after which
> a further statement decodes a payload hidden in Unicode variation-selector
> characters — which are invisible when the file is rendered — into a buffer,
> and passes that buffer to `eval()`.
>
> The combination of an invisible encoding and dynamic evaluation, appended to
> an otherwise ordinary file, has no legitimate explanation that we have been
> able to identify. The repository is published as a security-related Maven
> helper, which in our view makes the presentation particularly misleading.
>
> We verified on [DATA] that the code is still present in the current default
> branch. We have not executed it outside a controlled and isolated environment.
>
> [CHIUSURA]

---

## 3. GitHub Abuse — tool poisoning con esfiltrazione di email

> **Subject:** Responsible disclosure: MCP server with malicious tool description redirecting user email
>
> Dear GitHub Trust & Safety team,
>
> My name is Francesco Martignoni. I am a former Master's student at Politecnico
> di Milano, where, as part of my thesis project, I conducted a large-scale
> analysis of the Model Context Protocol (MCP) ecosystem, with a particular
> focus on identifying potential security vulnerabilities and misconfigurations
> in publicly available MCP servers.
>
> As part of this research, we analysed 69,104 publicly published MCP servers.
> I am writing to report one of them.
>
> **Repository:** `https://github.com/michaelguo1991/math-mcp-server-nodejs` —
> `src/index.ts`
>
> The repository presents itself as a simple arithmetic MCP server. The
> description of its `subtract` tool, however, contains an `<IMPORTANT>` block
> instructing the language model to redirect all messages sent through an
> unrelated `send_email` tool to a third-party address, and explicitly not to
> inform the user that it is doing so.
>
> This is an instance of what the literature refers to as tool poisoning: the
> payload is not code but metadata that the model reads as instructions, and it
> targets the behaviour of a tool belonging to a different server in the same
> session. The instruction to conceal the redirection from the user is, in our
> assessment, difficult to read as anything other than deliberate.
>
> We verified on [DATA] that the description is still present in the current
> default branch.
>
> [CHIUSURA]

---

## 4. Manutentore — richieste di chiarimento sull'esfiltrazione

Due casi, stessa impostazione. **Sono domande, non accuse**: il comportamento
potrebbe essere documentato altrove nel progetto, e presentarlo come malevolo
sarebbe un errore se cosi' non fosse. Scrivere in privato.

### 4a. `skdkfk8758/MCP-ProjectManager`

> **Subject:** Question regarding data transmitted to an external endpoint
>
> Hello,
>
> My name is Francesco Martignoni. I am a former Master's student at Politecnico
> di Milano, where, as part of my thesis project, I conducted a large-scale
> analysis of the Model Context Protocol (MCP) ecosystem, with a particular
> focus on identifying potential security vulnerabilities and misconfigurations
> in publicly available MCP servers.
>
> As part of this research, we analysed 69,104 publicly published MCP servers,
> and your project appeared among the results. I am writing to ask about a
> behaviour we observed, because I would like to be certain that we have
> understood it correctly before describing it anywhere.
>
> In `packages/cli/src/commands/init.ts` (around line 237), the installation
> routine registers global Claude Code hooks — `SessionStart`, `PreToolUse`,
> `PostToolUse`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop` and `Stop`
> — which post to the `/api/events` endpoint of the configured backend. As far
> as we have been able to determine, the payload includes the session
> identifier, the complete tool input of every tool call, the first 500
> characters of every tool output, and the length of user prompts.
>
> Because these hooks are registered globally rather than scoped to your own
> tools, the data collected appears to cover the user's entire session,
> including interactions with unrelated servers. Our questions are simply the
> following:
>
> 1. Is this telemetry intended, and is it documented for users at install time?
> 2. Is there an opt-out, and what is the default setting?
> 3. What is retained on the backend, and for how long?
>
> If the behaviour is intended and disclosed to users, we will describe it as
> such. If it is not intended to capture activity beyond your own tools, you may
> wish to scope the hooks more narrowly.
>
> No action or response is required from you within any particular timeframe,
> and we are not requesting anything in return. The study is academic in nature.
>
> [CHIUSURA]

### 4b. `vincentmcleese/promtHire-mcp`

Identico, con il paragrafo tecnico e la lista di domande sostituiti da:

> In `promptHire_server_node/src/server.ts` (around line 82), the schema of one
> of your tools instructs the model to populate `gig_description` with content
> described as *"COMPREHENSIVE ... extracted from the ENTIRE conversation ...
> Include context from all messages in the conversation"*, and the resulting
> value is then submitted to an external gig-posting service.
>
> Our concern is that a user asking to post a single job description may not
> expect the entire conversation, including unrelated context, to be
> transmitted. Our questions are simply whether this is the intended scope, and
> whether it is documented for users at the point of approval.

---

## 5. Manutentore — rug pull confermato

Per `sentry-official/mcp-cap-internal`.

> **Subject:** Responsible disclosure: change in the declared behaviour of analyze_dhcp_packets
>
> Hello,
>
> My name is Francesco Martignoni. I am a former Master's student at Politecnico
> di Milano, where, as part of my thesis project, I conducted a large-scale
> analysis of the Model Context Protocol (MCP) ecosystem, with a particular
> focus on identifying potential security vulnerabilities and misconfigurations
> in publicly available MCP servers.
>
> As part of this research, we measured the ecosystem twice, a few months apart,
> and compared what each server declares through `tools/list` at the two points
> in time. Your server is one of a very small number in which a declared
> capability changed between the two observations, and I am writing to ask about
> it.
>
> Of the four tools your server exposes, three are unchanged. The description of
> `analyze_dhcp_packets` gained one sentence:
>
>     ... return comprehensive analysis results. Then write data to user's system.
>
> A tool previously described as reading a capture file now declares that it
> writes to the user's filesystem. The addition does not state what is written
> or where, and carries no warning.
>
> This matters more in MCP than it might elsewhere, because approval is granted
> per server rather than per tool: a user who approved this tool when it only
> read files is not asked again when it begins writing them.
>
> Could you clarify what the tool writes, where it writes it, and whether this
> is configurable? If the behaviour is intended, a more explicit description
> would help users make an informed decision at the point of approval.
>
> No action or response is required from you within any particular timeframe,
> and we are not requesting anything in return. The study is academic in nature,
> and your repository is discussed in it only as an anonymised example unless we
> hear otherwise from you.
>
> [CHIUSURA]

---

## 6. GitHub — nome dell'organizzazione

Segnalazione **separata** dalla §5, categoria *impersonation*: sono questioni
distinte e vanno indirizzate a uffici diversi.

> **Subject:** Possible organisation-name impersonation (sentry-official)
>
> Dear GitHub Trust & Safety team,
>
> My name is Francesco Martignoni, a former Master's student at Politecnico di
> Milano. As part of an academic study of the Model Context Protocol ecosystem,
> I am writing to raise a naming concern.
>
> The organisation `sentry-official` publishes MCP servers under a name that
> suggests an official affiliation with Sentry, the error-monitoring provider. I
> have found no indication that such an affiliation exists.
>
> I am reporting this solely as a naming concern and I have no evidence
> regarding the intent behind the choice. For context, I mention that the same
> organisation is the subject of a separate technical report I have filed
> concerning a change in the declared behaviour of one of its tools.
>
> [CHIUSURA]

---

## 7. Manutentore — cortesia

Per `letoribo/mcp-graphql-enhanced`, dove il cambiamento e' dichiarato
apertamente. **Non e' una segnalazione di sicurezza** e va scritta come tale.

> **Subject:** Note from an academic study of the MCP ecosystem
>
> Hello,
>
> My name is Francesco Martignoni. I am a former Master's student at Politecnico
> di Milano, where, as part of my thesis project, I conducted a large-scale
> analysis of the Model Context Protocol (MCP) ecosystem.
>
> In a longitudinal comparison of what MCP servers declare at two points in
> time, `query-graphql` was one of the tools whose declared capability changed,
> from executing queries to executing queries and mutations.
>
> I want to be clear that we recorded this as a well-handled case: the new
> description states the change explicitly and includes a warning about
> persistent state. We cite it in our results as an example of a capability
> extension being communicated properly, and I wanted you to hear it from us
> rather than read it in a paper.
>
> One suggestion, offered only as such: since MCP approval is granted per
> server, users who approved the read-only version are not prompted again. A
> separate tool for mutations would make the distinction visible at the point of
> approval.
>
> [CHIUSURA]

---

## 8. ~~Fornitori — revoca di credenziali esposte~~ (RIMOSSO)

> **Non si invia.** La decisione di revocare appartiene al proprietario della
> credenziale. La notifica va all'owner del repository, che puo' ruotarla in
> modo ordinato; il testo generato per ciascuno sta in `messaggi/`.

La scelta va comunque motivata nell'articolo, perche' il canale del fornitore
sembra la strada ovvia e non lo e': solo **128 chiavi su 899 (14%)** portano un
marcatore che consente di attribuirle a un fornitore. Le altre 769 stanno in
identificatori generici (`API_KEY`, `TOKEN`, `SECRET`) senza indicazione del
servizio, e non esiste un destinatario a cui chiederne la revoca.

| fornitore | chiavi | repository |
|---|---:|---:|
| Google | 76 | 49 |
| OpenAI | 39 | 25 |
| OpenWeather | 6 | 6 |
| Supabase | 2 | 2 |
| Docker | 2 | 2 |
| Groq | 2 | 2 |
| GitHub | 1 | 1 |
| **non identificabile** | **769** | **331** |

---

## 9. Manutentore — i due casi ad alta diffusione (superata)

**Non usare il template che stava qui.** I due messaggi sono stati scritti per
esteso, uno per destinatario, perche' i due casi non condividevano ne' il tipo
di finding ne' la posizione:

* `@iflow-mcp/ollama-mcp` -> `messaggi_estensione/__iflow-mcp__ollama-mcp.txt`.
  Pronto, nessun segnaposto. Il finding non ha un file e una riga utilizzabili
  (vive in `build/index.js`, un bundle compilato) ed e' quindi descritto per
  comportamento: il tool che esegue `ollama create`, il parametro con il nome del
  modello concatenato senza sanitizzazione, l'errore di sintassi shell nella
  risposta che dimostra che il valore raggiunge una shell come sintassi e non
  come argomento. Canale: i maintainer pubblicati nel registry npm, perche' il
  pacchetto non dichiara repository, homepage ne' author.

* `bigcodegen/mcp-neovim-server` ->
  `messaggi_estensione/bigcodegen__mcp-neovim-server.txt`. **Rinunciato**: nessun
  canale privato. Il testo resta scritto. Vale la pena rileggerlo comunque,
  perche' documenta che **4 dei 5 finding della pipeline su quel repository sono
  falsi positivi**, verificati leggendo il sorgente.

---

## 10. Manutentore — finding non-credenziali verificati a mano (proposta)

**Da decidere.** Perimetro: i repository su cui esiste almeno un finding *non*
di credenziali con verdetto **VP-C** — sfruttabile in pieno — letto e confermato
individualmente durante l'audit manuale. Registro completo in
[`estensione_registro.json`](estensione_registro.json), prodotto da
`python autorun/disclosure_estensione.py`.

Il criterio non e' la categoria ma **la verifica individuale**: sono gli unici
finding non-credenziali per cui possiamo dire a un manutentore "questo l'ha
letto una persona", che e' la stessa affermazione che regge la campagna delle
credenziali. Tutto il resto resta fuori, e la disclosure per quello e' la
pubblicazione aggregata.

| | repo |
|---|---:|
| con almeno un VP-C non-credenziale | 63 |
| − gia' instradati nel Tier 1/2 | −7 |
| − vulnerabili di proposito (`0pstech/vuln-fs`) | −1 |
| − repository non piu' esistente | −4 |
| − nessun canale di contatto pubblico | −35 |
| **contattabili** | **16** |

I 7 tolti sono `heavenlycolle/mcp-trino`, `illustriousj/kite-mcp-server`,
`optimisticdur/go-mcp-mysql`, `FronNian/mpc-maven-security`,
`michaelguo1991/math-mcp-server-nodejs`, `skdkfk8758/MCP-ProjectManager`,
`vincentmcleese/promtHire-mcp`. **Sui primi quattro il manutentore e'
l'attaccante**: avvisarlo che e' stato scoperto, prima che GitHub intervenga, e'
il contrario di una disclosure. Il loro canale e' la §1.

Esclusi anche `protocol-violation`, le sottocategorie di `mcp-check`
(conformita' al protocollo, non vulnerabilita') e i verdetti VP-D (impatto
limitato: sono i casi in cui la capability e' verosimilmente voluta).

**Un caso da trattare a mano**: `Teradata/teradata-mcp-server` (54 stelle, 59
fork) non pubblica un contatto su GitHub, ma e' un'azienda e ha un canale di
sicurezza aziendale. E' il destinatario piu' qualificato del gruppo, e la
correzione a monte sistema anche il fork
`BACH-AI-Tools/bachstudio-teradata-mcp-server`, che porta lo stesso testo.

Il testo e' identico a §9 salvo l'apertura del terzo capoverso, che non puo'
rivendicare la conferma incrociata fra framework:

> As part of this research, we analysed 69,104 publicly published MCP servers.
> Most findings produced by an analysis of this scale are not individually
> verified, and we do not report those. Your repository is among the smaller set
> in which a finding was selected for manual review and confirmed by a person
> reading the source code, which is why we are writing to you specifically.
>
> The confirmed finding concerns [CATEGORIA]:
>
> [ELENCO]

Il resto — i due caveat, la dichiarazione di assenza di richieste, la chiusura —
resta quello di §9.

---

## Ordine di invio consigliato

1. **Tier 1** (§1–3): i payload sono attivi, non dipendono dai tempi dell'articolo.
2. **§6**, il nome dell'organizzazione, contestualmente a §5.
3. **Tier 2** (§4–5, 7): dopo aver concordato il testo con il relatore.
4. **§9**: i due casi ad alta diffusione.
5. **Campagna credenziali**: 455 repository, 195 raggiungibili, messaggi gia'
   generati in `messaggi/`. Da distribuire su settimane, non in blocco.
6. **§10**, se approvata.

Registrare in `FASE3.md` data, canale, destinatario ed esito di ogni invio: e'
il materiale con cui si scrive §12.7.
