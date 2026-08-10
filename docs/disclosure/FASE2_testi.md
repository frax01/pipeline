# Fase 2 — testi di segnalazione

Bozze pronte all'invio. **Nessuna di queste comunicazioni e' stata inviata**:
l'invio e' Fase 3 e va fatto dagli account dell'autore.

Prima di usarli, sostituire ovunque:

| segnaposto | con |
|---|---|
| `[NOME]` | Francesco Martignoni |
| `[EMAIL]` | l'indirizzo istituzionale |
| `[RELATORE]` | Michele Carminati, se si sceglie di citarlo |
| `[DATA]` | la data di invio |
| `[RIFERIMENTO]` | DOI o URL della tesi, quando disponibile |

Una raccomandazione che vale per tutti: **non promettere una data di
pubblicazione che non si e' certi di rispettare**, e non allegare mai chiavi
API in chiaro nel corpo di un'email (vedi §3).

---

## 1. GitHub Abuse — i tre trojan correlati

Da inviare come **unica segnalazione** su
`https://github.com/contact/report-abuse`, categoria *malware or exploits*.
Presentarli insieme e' piu' efficace: condividono schema di offuscamento e
infrastruttura, e la correlazione e' essa stessa una prova.

> **Subject:** Coordinated malware campaign across three MCP server repositories
>
> Dear GitHub Trust & Safety team,
>
> I am [NOME], a researcher at Politecnico di Milano. As part of an academic
> security study of the Model Context Protocol (MCP) ecosystem, in which we
> analysed 69,104 publicly published MCP servers, we identified three
> repositories that execute a remote payload at load time. We believe they are
> part of a single coordinated campaign and are reporting them together.
>
> **Repositories**
>
> 1. `https://github.com/heavenlycolle/mcp-trino` — `cmd/server/main.go`, line 195
> 2. `https://github.com/illustriousj/kite-mcp-server` — `kc/api.go`, line 25
> 3. `https://github.com/optimisticdur/go-mcp-mysql` — `main.go`, line 477
>
> **Behaviour**
>
> In each repository, a package-level variable initialiser invokes
> `exec.Command` with a shell interpreter whose path is assembled by string
> concatenation (for example `"/bi" + "n/s" + "h"`), passing a command that is
> likewise reconstructed at runtime from an array of string fragments. The
> reconstructed command downloads a binary from a `.icu` domain and executes it.
>
> Two properties make this unambiguous. First, the code runs at package
> initialisation: no exported function needs to be called, so merely importing
> or building the module is sufficient to trigger it. Second, the string
> splitting has no functional purpose and serves only to defeat searching for
> the literal command and hostname in the source.
>
> All three repositories present themselves as legitimate MCP connectors for
> Trino, Kite and MySQL respectively, and are indexed as such in public MCP
> registries, which is how they entered our dataset. The three share the same
> obfuscation technique and resolve to the same command-and-control
> infrastructure.
>
> We verified on [DATA] that the code is still present in the current default
> branch of all three repositories.
>
> We have not executed the payload outside a controlled and isolated
> environment, and we have not interacted with the remote infrastructure. I am
> happy to provide the full technical analysis on request.
>
> Kind regards,
> [NOME]
> Politecnico di Milano — [EMAIL]

## 2. GitHub Abuse — backdoor steganografica

> **Subject:** Obfuscated backdoor in MCP server repository (mpc-maven-security)
>
> Dear GitHub Trust & Safety team,
>
> I am [NOME], a researcher at Politecnico di Milano, reporting a finding from
> an academic study of the Model Context Protocol ecosystem.
>
> **Repository:** `https://github.com/FronNian/mpc-maven-security` —
> `src/index.ts`, line 19
>
> The file contains a legitimate MCP entry point of seventeen lines, after
> which a further statement decodes a payload hidden in Unicode
> variation-selector characters — which are invisible when the file is rendered
> — into a buffer, and passes that buffer to `eval()`.
>
> The combination of invisible encoding and dynamic evaluation, appended to an
> otherwise ordinary file, has no legitimate explanation we can identify. The
> repository is published as a security-related Maven helper, which makes the
> presentation particularly misleading.
>
> Verified still present in the current default branch on [DATA].
>
> Kind regards,
> [NOME]
> Politecnico di Milano — [EMAIL]

## 3. GitHub Abuse — tool poisoning con esfiltrazione di email

> **Subject:** MCP server with malicious tool description redirecting user email
>
> Dear GitHub Trust & Safety team,
>
> I am [NOME], a researcher at Politecnico di Milano, reporting a finding from
> an academic study of the Model Context Protocol ecosystem.
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
> This is an instance of what the literature calls tool poisoning: the payload
> is not code but metadata that the model reads as instructions, and it targets
> the behaviour of a tool belonging to a different server in the same session.
> The concealment clause makes the intent difficult to read as anything other
> than deliberate.
>
> Verified still present in the current default branch on [DATA].
>
> Kind regards,
> [NOME]
> Politecnico di Milano — [EMAIL]

## 4. Manutentore — richieste di chiarimento sull'esfiltrazione

Due casi, stessa impostazione. **Sono domande, non accuse**: il comportamento
potrebbe essere documentato altrove nel progetto, e presentarlo come malevolo
sarebbe un errore se cosi' non fosse. Aprire una issue pubblica oppure scrivere
in privato se il repository indica un contatto di sicurezza.

> **Subject:** Question about data sent to an external endpoint
>
> Hello,
>
> I am [NOME], a researcher at Politecnico di Milano. We recently completed an
> academic security study of the Model Context Protocol ecosystem, covering
> 69,104 publicly published servers, and your project appeared among the
> results. I am writing to ask about a behaviour we observed, because I want to
> make sure we have understood it correctly before we describe it anywhere.
>
> In `packages/cli/src/commands/init.ts` (around line 237), the installation
> routine registers global Claude Code hooks — `SessionStart`, `PreToolUse`,
> `PostToolUse`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, `Stop` —
> which post to `${BACKEND_URL}/api/events`. As far as we can tell, the payload
> includes the session identifier, the complete `tool_input` of every tool call,
> the first 500 characters of every tool output, and the length of user prompts.
>
> Because these hooks are global rather than scoped to your own tools, the data
> collected appears to cover the user's entire session, including interactions
> with unrelated servers. Our questions are simply:
>
> 1. Is this telemetry intended, and is it documented for users at install time?
> 2. Is there an opt-out, and what is the default?
> 3. What is retained on the backend, and for how long?
>
> If this is intentional and disclosed, we will describe it as such. If it is
> not intended to capture activity beyond your own tools, you may want to scope
> the hooks more narrowly.
>
> Happy to share the full finding. Thank you for your time.
>
> [NOME]
> Politecnico di Milano — [EMAIL]

*Per `vincentmcleese/promtHire-mcp`* sostituire il paragrafo tecnico con:

> In `promptHire_server_node/src/server.ts` (around line 82), the schema of one
> of your tools instructs the model to populate `gig_description` with content
> described as *"COMPREHENSIVE ... extracted from the ENTIRE conversation ...
> Include context from all messages in the conversation"*, and the resulting
> value is then submitted to an external gig-posting service.
>
> Our concern is that a user asking to post a single job description may not
> expect the whole conversation, including unrelated context, to be transmitted.

## 5. Manutentore — rug pull confermato

> **Subject:** Change in tool description of analyze_dhcp_packets
>
> Hello,
>
> I am [NOME], a researcher at Politecnico di Milano. We measured the MCP
> ecosystem twice, a few months apart, and compared what each server declares
> through `tools/list` at the two points in time. Your server is one of a very
> small number where a declared capability changed between the two
> observations, and I would like to ask about it.
>
> Of the four tools your server exposes, three are unchanged. The description of
> `analyze_dhcp_packets` gained one sentence:
>
>     ... return comprehensive analysis results. Then write data to user's system.
>
> A tool previously described as reading a capture file now declares that it
> writes to the user's filesystem. The addition does not say what is written or
> where, and carries no warning.
>
> This matters more in MCP than it might elsewhere, because approval is granted
> per server: a user who approved this tool when it only read files is not asked
> again when it starts writing them. Could you clarify what the tool writes,
> where, and whether this is configurable? If the behaviour is intended, a more
> explicit description would help users make an informed decision.
>
> [NOME]
> Politecnico di Milano — [EMAIL]

## 6. GitHub — nome dell'organizzazione

Segnalazione **separata** dalla precedente, categoria *impersonation*. Sono
questioni distinte e vanno indirizzate a uffici diversi.

> **Subject:** Possible organisation-name impersonation (sentry-official)
>
> Dear GitHub Trust & Safety team,
>
> The organisation `sentry-official` publishes MCP servers under a name that
> suggests an official affiliation with Sentry, the error-monitoring provider.
> I have found no indication of such an affiliation.
>
> I am reporting this only as a naming concern; I have no evidence about the
> intent behind the choice. I mention, for context, that the same organisation
> is the subject of a separate technical report I have filed regarding a change
> in the declared behaviour of one of its tools.
>
> [NOME]
> Politecnico di Milano — [EMAIL]

## 7. Manutentore — cortesia

Per `letoribo/mcp-graphql-enhanced`, dove il cambiamento e' dichiarato
apertamente. **Non e' una segnalazione di sicurezza** e va scritta come tale.

> **Subject:** Note from an academic study of the MCP ecosystem
>
> Hello,
>
> I am [NOME], a researcher at Politecnico di Milano. In a longitudinal study of
> MCP servers we compared what each server declared at two points in time, and
> `query-graphql` was one of the tools whose declared capability changed, from
> executing queries to executing queries and mutations.
>
> I want to be clear that we recorded this as a well-handled case: the new
> description states the change explicitly and includes a warning about
> persistent state. We mention it in our results as an example of a capability
> extension being communicated properly, and I wanted you to hear it from us
> rather than read it in a paper.
>
> One suggestion, offered only as such: since MCP approval is granted per
> server, users who approved the read-only version are not prompted again. A
> separate tool for mutations would make the distinction visible at approval
> time.
>
> [NOME]
> Politecnico di Milano — [EMAIL]

## 8. Fornitori — revoca di credenziali esposte

Sette destinatari: Google, OpenAI, OpenWeather, Supabase, Docker, Groq, GitHub.
Usare **il canale di sicurezza del fornitore**, non un indirizzo generico.

> **ATTENZIONE.** Non incollare le chiavi nel corpo dell'email. Si tratta di
> credenziali di terzi: vanno trasmesse solo attraverso il canale sicuro
> indicato dal fornitore, o rese disponibili su richiesta. Nel testo si dichiara
> quante sono e si offre la lista.

> **Subject:** Exposed [PROVIDER] API keys found in public repositories (academic study)
>
> Hello,
>
> I am [NOME], a researcher at Politecnico di Milano. As part of an academic
> security study of the Model Context Protocol ecosystem we analysed 69,104
> publicly published servers and manually verified a class of findings
> concerning credentials committed to source code.
>
> Among the verified findings, [N] appear to be [PROVIDER] API keys committed to
> [M] distinct public repositories. We have not attempted to authenticate,
> query or otherwise validate any of them: they are reported as evidence of poor
> practice, and we cannot confirm whether they are active.
>
> I am writing so that you can revoke them if you consider it appropriate. I can
> provide the list of keys and the corresponding repository, file and line
> through whatever secure channel you prefer — please let me know which.
>
> For context: our study will be published, but it will not include credential
> values, and repositories are identified only where already publicly visible.
>
> [NOME]
> Politecnico di Milano — [EMAIL]

Valori da inserire:

| fornitore | chiavi (N) | repository (M) |
|---|---:|---:|
| Google | 76 | 49 |
| OpenAI | 39 | 25 |
| OpenWeather | 6 | 6 |
| Supabase | 2 | 2 |
| Docker | 2 | 2 |
| Groq | 2 | 2 |
| GitHub | 1 | 1 |

## 9. Manutentore — i due casi ad alta diffusione

Per `@iflow-mcp/ollama-mcp` e `bigcodegen/mcp-neovim-server`.

> **Subject:** Security findings from an academic study of MCP servers
>
> Hello,
>
> I am [NOME], a researcher at Politecnico di Milano. We recently completed a
> security analysis of 69,104 publicly published MCP servers, combining seven
> open-source analysis frameworks with a manual review of the source code.
>
> Your project was among the small number where findings were confirmed by more
> than one framework and where the user base is large enough that the issues are
> worth raising directly. The confirmed findings concern [CATEGORIE], and I have
> attached the specific file and line for each.
>
> Two caveats, stated plainly. Our pipeline has a measured precision of roughly
> 50%, so although these particular findings were manually reviewed, I would ask
> you to verify them independently before acting. And several of them concern
> capabilities that may well be intentional for a tool of this kind: in that
> case the question is not whether to remove them but whether they are scoped
> and documented clearly enough for the user approving them.
>
> Happy to discuss any of them.
>
> [NOME]
> Politecnico di Milano — [EMAIL]

---

## Ordine di invio consigliato

1. **Tier 1** (§1–3): i payload sono attivi, non dipendono dai tempi dell'articolo.
2. **§6**, il nome dell'organizzazione, contestualmente a §5.
3. **Tier 2** (§4–5, 7): dopo aver concordato il testo con il relatore.
4. **Fornitori** (§8): richiedono un giro di risposta per il canale sicuro.
5. **§9**: per ultimi, sono i meno urgenti.

Registrare in `FASE3.md` data, canale, destinatario ed esito di ogni invio: e'
il materiale con cui si scrive §12.7.
