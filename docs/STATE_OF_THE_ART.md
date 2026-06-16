# State of the Art — Paper analizzati per la tesi MCP

Documento di tracking dei paper accademici letti per posizionare il lavoro di tesi. Per ogni paper: titolo, autori, tipo di studio, metodologia utilizzata, dataset analizzato (se empirico), risultati chiave.

I paper sono raggruppati per **tipo di contributo** (survey vs empirical vs benchmark vs defense framework) per facilitare il confronto con il mio lavoro.

Path PDF: `C:\Users\francesco\Desktop\Tesi\Paper MCP\`

**Convenzioni**:
- ✅ = paper **letto e analizzato** (PDF in `Tesi/Paper MCP/`)
- ⚠️ NON LETTO = paper **citato da fonti esterne** (es. Gemini deep research) ma non ancora analizzato direttamente — da approfondire

---

## Sommario rapido

| # | Paper | Tipo | Server analizzati | Validazione | Stato |
|---|-------|------|------------------:|-------------|-------|
| 1 | **Landscape, Security Threats** (Hou et al.) | Vision/Survey | 0 (PoC artigianali) | 16 PoC manuali in lab isolato | ✅ |
| 2 | **A Survey of LLM-Driven AI Agent Communication** | Survey | — | Esperimenti su MCP + A2A | ✅ |
| 3 | **Open Challenges in Multi-Agent Security** | Position paper | — | Solo discussione teorica | ✅ |
| 4 | **McpGuard Analysis** (Bin Wang et al.) | Survey defense | — | Survey di soluzioni esistenti | ✅ |
| 5 | **MCP at First Glance** (Hasan et al.) | **Empirical** | **1.899 server** | Static analysis + MCP scanner | ✅ |
| 6 | **We Urgently Need Privilege Management** (Zhihao Li et al.) | **Empirical** | **2.562 server** | Static analysis automatizzata | ✅ |
| 7 | **Toward Understanding Security Issues** (Xiaofan Li, Gao) | **Empirical** | **67.057 server** | Qualitative + quantitative (6 registri) | ✅ |
| 8 | **Mind Your Server** (Zhao et al.) | **Empirical** | **12.230 tool, 1.360 server** | MCP-SEC scanner | ✅ |
| 9 | **Securing AI Agent Execution** (Bühler et al.) | **Empirical** | **296 server top** | Policy generation, AgentBound | ✅ |
| 10 | **McpTox** (Wang et al.) | Benchmark | 45 server live, 353 tool, 1.312 test | 20 agent LLM testati | ✅ |
| 11 | **MCP Security Bench 1 (MSB)** (Zhang et al.) | Benchmark | 400+ tool, 10 domini | 9 LLM agent, 2.000 attack instances | ✅ |
| 12 | **MCP Security Bench 2 (MCPSECBENCH)** (Yang et al.) | Benchmark | — | 17 tipi attacco × 3 provider (Claude/OpenAI/Cursor) | ✅ |
| 13 | **Systematic Analysis (MCPLIB)** (Guo et al.) | Benchmark | — | 31 metodi attacco, 4 classi | ✅ |
| 14 | **MCP Safety Audit / McpSafetyScanner** (Radosevich, Halloran) | Defense tool | — | Scanner agentic | ✅ |
| 15 | **MCP Guardian** (Kumar et al.) | Defense framework | — | WAF + auth + rate-limiting | ✅ |
| 16 | **MCP-Guard framework** (Xing et al.) | Defense framework | — | MCP-AttackBench 70k samples, E5 detector 96% | ✅ |
| 17 | **ETDI** (Bhatt et al.) | Defense framework | — | OAuth + JWT extension | ✅ |
| 18 | **Enterprise-Grade Security for MCP** (Narajala, Habler) | Defense framework | — | Zero Trust, mitigation patterns | ✅ |
| 19 | **Evaluation Report on MCP Servers (MCPBench)** (Luo et al.) | Performance | ~10 server | NON sicurezza — accuracy/tempo/token | ✅ |
| 20 | **Security Analysis of Agentic AI Communication Protocols** (Louck et al.) | Comparative | CORAL/ACP/A2A | NON MCP — protocolli agent-to-agent | ✅ |
| 21 | **Compatibility at a Cost** (Yang, Bai, Lu) | Empirical SDK analysis | **10 SDK MCP ufficiali** | Static analysis, 1.265 rischi identificati, attacchi PyTy/PyTn/PnTy formalizzati | ⚠️ NON LETTO |
| 22 | **SoK: Security and Safety in MCP Ecosystem** | Survey/SoK | — | Tassonomia threat completa, convergenza hallucination LLM ↔ RCE | ⚠️ NON LETTO |

**Cosa fa il mio lavoro che nessuno di questi fa:**
- **60.205 server GitHub + 8.899 NPX = 69.104 server analizzati** (36× più del prossimo, Toward Understanding Security Issues con 67k qualitative-only)
- **7 framework di scanning combinati** (mcp-scan, mcp-watch, mcp-guard, mcp-shield, mcp-security-scan, mcp-check, tool_fuzzing)
- **Pipeline Stage 1 + 2A (HC rules) + 2B (Sonnet in-chat)** con validazione blind n=50/cat
- **Cross-framework consensus** (tier per number-of-framework-agreement)
- **22.955 VP totali** misurati (raw post-merge NPX parziale)

---

## A — Survey / Vision papers (taxonomia teorica, niente large-scale empirical)

### 1. Landscape, Security Threats and Future Research Directions
**Hou, Zhao, Wang, Wang** (Huazhong University of Science and Technology) — arXiv 2503.23278v3, Oct 2025

- **Obiettivo**: prima vision/survey sistematica MCP — landscape + tassonomia minacce + recommendations
- **Metodologia**: definizione lifecycle MCP server (4 fasi: creation/deployment/operation/maintenance, 16 attività) + tassonomia 16 minacce × 4 archetipi attaccante
- **Validazione**: ❌ NON empirica. Costruzione manuale di **16 PoC MCP server** in ambiente isolato, uno per ogni minaccia. Esempio: `github-mcp` vs `mcp-github` per dimostrare typosquatting.
- **Quote chiave**: "we constructed proof-of-concept (PoC) MCP servers corresponding to each identified risk type within an isolated environment... the goal of this PoC is to demonstrate security risks and feasibility rather than to evaluate attack success rates"
- **Dati**: solo Tabelle compilate manualmente (26 MCP marketplaces tramite "manual inspection")
- **Risultati**: tassonomia + safeguard recommendations
- **Posizionamento vs mio lavoro**: paper di riferimento per la tassonomia. Il mio lavoro fornisce la **validazione empirica large-scale** che questo paper esplicitamente lascia come future work.

### 2. A Survey of LLM-Driven AI Agent Communication
**Kong et al.** (Zhejiang University + altri) — arXiv 2506.19676v3, Jul 2025

- **Obiettivo**: survey completa sulla sicurezza della comunicazione tra agent LLM (non solo MCP — copre anche A2A, ANP, ACP)
- **Metodologia**: definizione del lifecycle agent communication (user-agent / agent-agent / agent-environment), analisi protocolli + rischi + countermeasure per ogni fase
- **Validazione**: esperimenti su MCP + A2A per illustrare vulnerabilità (non large-scale scan)
- **Risultati**: tassonomia rischi + outlook future directions
- **Posizionamento vs mio lavoro**: survey più ampia (anche oltre MCP). Cita 327 referenze. Il mio lavoro focus solo MCP ma più profondo empiricamente.

### 3. Open Challenges in Multi-Agent Security
**Schroeder de Witt** (Oxford) — arXiv 2505.02077v1, May 2025

- **Obiettivo**: introdurre "Multi-Agent Security" come nuovo campo di ricerca
- **Metodologia**: position paper. Tassonomia threat + trade-off security/performance + research agenda
- **Validazione**: ❌ nessuna empirica. Solo discussione teorica e scenari (collusion, swarm attacks, ecc.)
- **Risultati**: research agenda per sicurezza in agent systems decentralizzati
- **Posizionamento vs mio lavoro**: paper concettuale, non confrontabile direttamente. Utile per inquadramento ampio.

### 4. McpGuard: Automatically Detecting Vulnerabilities in MCP Servers — Bin Wang et al.
**Bin Wang et al.** (Peking University + Tencent) — arXiv 2510.23673v1, Oct 2025

- **Nota**: NON è il framework di scanning ma una **survey delle difese** (titolo confusing)
- **Obiettivo**: analizzare il panorama di sicurezza MCP e survey delle defense strategies esistenti
- **Metodologia**: classifica 3 categorie di minacce (agent hijacking / web vulnerabilities / supply chain) + survey defense strategies
- **Validazione**: survey di letteratura, nessuna empirical analysis propria
- **Risultati**: "MCP security represents a paradigm shift where the attack surface extends from traditional code execution to semantic interpretation of natural language metadata"
- **Posizionamento vs mio lavoro**: utile come reference per la tassonomia difese; il mio lavoro USA molti dei framework citati.

### 4-bis. ⚠️ NON LETTO — Systematization of Knowledge: Security and Safety in the Model Context Protocol Ecosystem
**Autori da verificare** — arXiv 2512.08290, Dec 2025 — https://arxiv.org/pdf/2512.08290

- **Tipo**: paper SoK (Systematization of Knowledge) — verificato esistente dall'utente
- **Obiettivo** (per quanto noto da fonti secondarie / Gemini deep research): delineare il panorama completo delle minacce di sicurezza nell'ecosistema MCP, sistematizzando la letteratura esistente
- **Metodologia** (presunta): survey + tassonomia teorica
- **Risultati chiave riportati**:
  - Server debolmente autenticati, tool con privilegi eccessivi e controlli di integrità fragili consentono regolarmente RCE, furto token e movimento laterale
  - **L'MCP estende la superficie di attacco dall'esecuzione tradizionale del codice all'interpretazione semantica dei metadati in linguaggio naturale**
  - I classici metodi di verifica formale sono insufficienti
  - Auspica framework ibridi che combinino controlli statici sul codice degli strumenti con validazione dinamica degli output LLM (red-teaming)
- **Posizionamento vs mio lavoro** (ipotetico, da confermare a lettura): potrebbe essere LA SoK di riferimento più aggiornata. Il mio lavoro (7 framework combinati statici + dinamici) realizza concretamente il "framework ibrido" che questa SoK auspica.
- **TO-DO**: scaricare e leggere il PDF da arxiv per estrarre numeri esatti e citazioni precise.

---

## B — Empirical Large-Scale Analysis

### 5. MCP at First Glance: Studying the Security and Maintainability of MCP Servers
**Hasan, Li, Fallahzadeh, Rajbahadur, Adams, Hassan** (Queen's University) — arXiv 2506.13538v4, Jun 2025

- **Obiettivo**: prima large-scale empirical study di MCP server (health, security, maintainability)
- **Metodologia**: hybrid analysis pipeline = general-purpose static analysis tool + MCP-specific scanner
- **Dataset**: **1.899 open-source MCP server**
- **Validazione**: empirical, scansione automatizzata + health metrics
- **Risultati**:
  - 8 categorie di vulnerabilità identificate (solo 3 overlap con SW tradizionale)
  - 7.2% server con vulnerabilità generali
  - **5.5% server con tool poisoning MCP-specific**
  - 66% code smells, 14.4% bug pattern tradizionali
- **Posizionamento vs mio lavoro**: il paper empirico più vicino al mio approccio. **Il mio lavoro è 36× più grande** (69.104 vs 1.899) e usa **7 framework** vs 1 hybrid pipeline.

### 6. We Urgently Need Privilege Management in MCP: A Measurement of API Usage
**Zhihao Li, Kun Li, Boyang Ma, Minghui Xu, Yue Zhang, Xiuzhen Cheng** (Shandong University) — arXiv 2507.06250v1, Jul 2025

- **Obiettivo**: misurare uso di API privilegiate nei server MCP (privilege management)
- **Metodologia**: automated static analysis framework
- **Dataset**: **2.562 server MCP** in 23 categorie funzionali
- **Risultati**:
  - 1.438 server usano network API
  - 1.237 system resource API
  - 613 file resource
  - "Developer Tools" e "API Development" sono le categorie più API-intensive
  - I plugin meno popolari hanno spesso percentuali sproporzionate di operazioni high-risk
- **Posizionamento vs mio lavoro**: complementare. Loro misurano **quanti server usano API privilegiate**, io misuro **quanti server hanno vulnerabilità reali esfiltrabili**. Il mio dataset è 27× più grande.

### 7. Toward Understanding Security Issues in the MCP Ecosystem
**Xiaofan Li, Xing Gao** (University of Delaware) — arXiv 2510.16558v1, Oct 2025

- **Obiettivo**: prima security analysis comprehensive dell'**ecosistema** MCP (host + registry + server)
- **Metodologia**: qualitative analysis (mancanza output verification, vetting registry) + quantitative dataset analysis
- **Dataset**: **67.057 server** da 6 registri pubblici (mcp.so, MCP Market, MCP Store, Pulse MCP, Smithery, npm)
- **Validazione**: misura quanti server possono essere "hijacked" via mancanza di vetting nei registry
- **Risultati**:
  - LLM-generated outputs non verificati dagli host → server malevoli possono manipolare comportamento
  - Substantial number di server hijackable
  - Disclosure responsabile ai 6 registri
- **Posizionamento vs mio lavoro**: dataset GRANDE come il mio (67k vs 60k GitHub). Ma loro è **qualitative + count** (quanti server hijackable), il mio è **per-server vulnerability scan con 7 framework** (categorie specifiche, VP/FP, risk score). Più complementari che sovrapposti.

### 8. Mind Your Server: Parasitic Toolchain Attacks on the MCP Ecosystem
**Shuli Zhao, Qinsheng Hou, Zihan Zhan, Yanhao Wang, Yuchong Xie, Yu Guo, Libo Chen, Shenghong Li, Zhi Xue** (Shanghai Jiao Tong University) — arXiv 2509.06572v2, Sep 2025

- **Obiettivo**: rivela una NUOVA classe di attacco — Parasitic Toolchain Attacks (MCP-UPD: Unintended Privacy Disclosure)
- **Metodologia**: design attack flow in 3 fasi (Parasitic Ingestion / Privacy Collection / Privacy Disclosure). Costruzione MCP-SEC scanner.
- **Dataset**: **12.230 tool across 1.360 MCP server** — "first large-scale security census"
- **Validazione**: MCP-SEC scanner sui 12k tool
- **Risultati**:
  - MCP manca di context-tool isolation e least-privilege enforcement
  - Ecosistema "rife with real-world exploitable gadgets"
- **Posizionamento vs mio lavoro**: focus su classe di attack specifica (toolchain). Il mio lavoro è più broad (8+ classi di vuln). Loro analizzano 1.360 server vs miei 69k.

### 9. Securing AI Agent Execution / AgentBound
**Christoph Bühler, Matteo Biagiola, Luca Di Grazia, Guido Salvaneschi** (University of St. Gallen / USI) — arXiv 2510.21236v2, Oct 2025

- **Obiettivo**: AgentBound — primo access control framework per MCP server (Android-style permission model)
- **Metodologia**: declarative policy mechanism + enforcement engine (no MCP server modification needed)
- **Dataset**: **296 MCP server più popolari**
- **Validazione**: empirical — auto-generate policy from source code, test blocking malicious behavior
- **Risultati**:
  - **80.9% accuracy** in generazione automatica policy da source code
  - Blocca majority delle minacce con overhead minimo
- **Posizionamento vs mio lavoro**: propone una soluzione (framework), io misuro il problema. Complementari.

### 9-bis. ⚠️ NON LETTO — Compatibility at a Cost: Systematic Discovery and Exploitation of MCP Clause-Compliance Vulnerabilities
**Yang, Bai, Lu** — arXiv 2603.10163, Mar 2026 (da verificare la data esatta)

- **Obiettivo** (da fonti secondarie / Gemini deep research): dissezionare formalmente il protocollo MCP per scoprire vulnerabilità sistematiche derivanti dalla rilassatezza della specifica
- **Metodologia** (presunta):
  - Analisi formale della specifica MCP
  - Static analysis su **10 SDK MCP ufficiali** scritti in linguaggi multipli
- **Risultati chiave riportati**:
  - **Il 78.5% delle clausole MCP è opzionale o condizionale** (rilassatezza voluta per massima compatibilità con diversi agent IA)
  - **1.265 potenziali rischi** identificati derivanti da implementazioni non conformi alle best practice
  - **Formalizzazione di 3 nuove classi di attacco "compatibility-abusing"**:
    - **PyTy** (Silent Tool Injection): iniezioni di prompt silenziose direttamente nei metadati degli strumenti, invisibili nei log standard
    - **PyTn** (Capability Assumption Attacks): basati su assunzioni di capacità errate nei gestori `resources/list`
    - **PnTy** (Timing DoS): sfruttano l'handler `ping` per Denial of Service basati sulle tempistiche
- **Importanza per il mio lavoro**: ⭐ **base teorica del framework mcp-check** (uno dei 7 che uso). Il GitHub di `piiiico/mcp-check` recita: *"Single-file MCP security scanner. Tests 7 vulnerability classes from arxiv 2603.10163"*. Quindi le categorie testate da mcp-check (PyTy/PyTn/PnTy/CORS/auth) derivano direttamente da questo paper.
- **Posizionamento vs mio lavoro**: paper teorico/formal-analysis su SDK. Il mio lavoro applica mcp-check (che implementa la tassonomia di questo paper) a 69.104 server reali — fornendo la prevalence empirica delle vulnerabilità che loro hanno formalizzato.
- **TO-DO**: verificare data esatta arXiv (l'ID 2603 = Marzo 2026 è sospetto, possibile typo per 2503.10163 o 2510.10163). Scaricare PDF e estrarre numeri.

---

## C — Benchmark / Attack Test Suite

### 10. MCPTox: Benchmark for Tool Poisoning Attack on Real-World MCP Servers
**Zhiqiang Wang, Yichao Gao, Yanting Wang, Suyuan Liu, Haifeng Sun, Haoran Cheng, Guanquan Shi, Haohua Du, Xiangyang Li** (USTC + Beihang) — arXiv 2508.14925v1, Aug 2025

- **Obiettivo**: primo benchmark sistematico Tool Poisoning Attack
- **Metodologia**: 3 attack template, few-shot learning per generare 1.312 test case su 10 categorie di rischio
- **Dataset**: **45 live real-world MCP server, 353 tool autentici**
- **Validazione**: testato su **20 LLM agent prominenti**
- **Risultati**:
  - o1-mini ha attack success rate del **72.8%**
  - Modelli più capable sono più vulnerabili (paradosso instruction-following)
  - Claude-3.7-Sonnet ha il refused rate più alto: comunque < 3%
- **Posizionamento vs mio lavoro**: benchmark per LLM defense, non scan dei server. Complementare al mio mcp-shield (anche lui semantic LLM-based).

### 11. MSB: MCP Security Bench (Benchmarking Attacks Against MCP in LLM Agents)
**Dongsen Zhang, Zekun Li, Xu Luo, Xuannan Liu, Peipei Li, Wenjun Xu** (BUPT + UCSB) — arXiv 2510.15994v1, Oct 2025

- **Obiettivo**: first end-to-end evaluation suite per misurare resistenza agent LLM ad attacchi MCP
- **Metodologia**: tassonomia 12 attacchi (name collision, preference manipulation, prompt injection nelle tool description, OOO parameter requests, user-impersonating, false-error escalation, tool-transfer, retrieval injection, mixed)
- **Dataset**: 10 domini, 400+ tool, **2.000 attack instance**
- **Validazione**: **9 popular LLM agent** valutati
- **Metric**: Net Resilient Performance (NRP) — trade-off security/performance
- **Risultati**: "Models con stronger performance sono più vulnerabili" (concorda con MCPTox)
- **Posizionamento vs mio lavoro**: benchmark per LLM, non per server.

### 12. MCPSECBENCH: Systematic Security Benchmark and Playground for MCP
**Yixuan Yang, Daoyuan Wu, Yufan Chen** (University of Twente + Lingnan + CityU Shenzhen) — arXiv 2508.13220v2, Aug 2025

- **Obiettivo**: prima formalizzazione sistematica attack surface MCP + playground modulare
- **Metodologia**: tassonomia **17 attacchi su 4 attack surface** (user interaction, client, transport, server)
- **Dataset**: cross-provider — Claude / OpenAI / Cursor
- **Validazione**: empirical su 3 provider
- **Risultati**:
  - **>85% degli attacchi compromettono almeno una piattaforma**
  - Core vulnerabilities universalmente presenti
  - Protezioni esistenti hanno poco effetto
- **Posizionamento vs mio lavoro**: benchmark/playground orientato a testing nuovi attacchi. Il mio lavoro misura prevalenza nel mondo reale.

### 13. Systematic Analysis of MCP Security / MCPLIB
**Yongjian Guo, Puzhuo Liu, Wanlun Ma, Zehang Deng, Xiaogang Zhu, Peng Di, Xi Xiao, Sheng Wen** (Tsinghua + Ant Group + Swinburne + Adelaide + UNSW) — arXiv 2508.12538v1, Aug 2025

- **Obiettivo**: MCPLIB — MCP Attack Library con tassonomia esaustiva
- **Metodologia**: **31 attack method** in 4 classi (direct tool injection / indirect tool injection / malicious user / LLM inherent)
- **Validazione**: experimenti quantitativi sull'efficacia di ogni attacco
- **Risultati**:
  - Agent hanno cieca dipendenza dalle tool description
  - Sensibilità ad attacchi file-based
  - Chain attack che sfruttano shared context
  - Difficoltà a distinguere external data da executable commands
- **Posizionamento vs mio lavoro**: tassonomia molto granulare (31 attacchi). Il mio lavoro mappa la maggior parte di queste categorie nei 7 framework.

---

## D — Defense Framework Papers

### 14. MCP Safety Audit / McpSafetyScanner
**Brandon Radosevich, John T. Halloran** (Leidos) — arXiv 2504.03767v2, Apr 2025

- **Obiettivo**: dimostrare che MCP allows major security exploits + proporre McpSafetyScanner
- **Metodologia**: PoC di attacchi + costruzione safety auditing tool
- **Tool**: **McpSafetyScanner** — agentic tool che usa multipli agent per:
  - Generare adversarial samples per tool/resource del server
  - Cercare vulnerabilità + remediation
  - Generare security report
- **Validazione**: dimostrazione su LLM industry-leading
- **Risultati**: code execution, remote access control, credential theft tutti dimostrati
- **Posizionamento vs mio lavoro**: McpSafetyScanner è un tool agent-based simile in spirito ai framework che ho usato. Non sovrapposto direttamente.

### 15. MCP Guardian: Security-First Layer for MCP-Based AI System
**Sonu Kumar et al.** (Sporo Health + Involead + Capgemini + IIT Roorkee + Deloitte + altri) — 2025

- **Obiettivo**: framework defense MCP con auth + rate-limiting + logging + tracing + WAF scanning
- **Metodologia**: defense-in-depth layer
- **Validazione**: real-world scenarios + empirical testing
- **Risultati**: mitigation efficace con overhead minimo
- **Posizionamento vs mio lavoro**: defense framework, non scanner. Ortogonale.

### 16. MCP-Guard Framework: 3-Stage Detection Pipeline
**Wenpeng Xing, Zhonghao Qi, Yupeng Qin, Yilin Li, Caini Chang, Jiahui Yu, Changting Lin, Zhenzhen Xie, Meng Han** (Zhejiang University + CUHK + Shandong) — arXiv 2508.10991v1, Aug 2025

- **Obiettivo**: defense architecture multi-stage per LLM-tool interactions
- **Metodologia**: 3-stage detection pipeline
  - Stage 1: static scanning (sub-2ms latency)
  - Stage 2: deep neural detector (E5 fine-tuned, **96.01% accuracy**)
  - Stage 3: LLM arbitrator per ridurre FP
- **Dataset training**: **MCP-AttackBench — 70.000+ samples** (public datasets + GPT-4 augmented)
- **Posizionamento vs mio lavoro**: defense framework. Il loro detector E5 potrebbe essere usato nella mia pipeline come Stage 2 alternativo.

### 17. ETDI: Enhanced Tool Definition Interface with OAuth + Policy-Based Access Control
**Manish Bhatt, Vineeth Sai Narajala, Idan Habler** (OWASP + AWS + Intuit) — arXiv 2506.01333v1, Jun 2025

- **Obiettivo**: estensione MCP per mitigare Tool Squatting + Rug Pull
- **Metodologia**: cryptographic identity verification + immutable versioned tool definitions + OAuth 2.0 scopes via JWT
- **Validazione**: design proposal + esempi
- **Posizionamento vs mio lavoro**: defense extension proposal. Le minacce che mitigano (typosquat, rug pull) sono le stesse del mio mcp-security-scan (rug-pull) e mcp-watch (tool-poisoning).

### 18. Enterprise-Grade Security for MCP: Frameworks and Mitigation Strategies
**Vineeth Sai Narajala, Idan Habler** (AWS + Intuit) — arXiv 2504.08623v2, Apr 2025

- **Obiettivo**: enterprise-grade mitigation framework con Zero Trust Architecture
- **Metodologia**: systematic threat modeling + analysis of MCP implementations + actionable patterns
- **Risultati**: framework pratico (Zero Trust, Defense-in-Depth) per adozione enterprise sicura
- **Posizionamento vs mio lavoro**: framework di sicurezza non scanner. Riferimento utile per le sezioni di remediation della tesi.

---

## E — Performance Evaluation (NON security)

### 19. Evaluation Report on MCP Servers (MCPBench)
**Zhiling Luo, Xiaorong Shi, Xuanrui Lin, Jinyang Gao** (Alibaba Cloud) — arXiv 2504.11094v2, Apr 2025

- **Obiettivo**: valutare effectiveness/efficiency degli MCP server (NON sicurezza)
- **Metodologia**: MCPBench framework — task web search + database search
- **Metric**: accuracy, time, token usage
- **Dataset**: ~10 MCP server widely-used (Brave Search, DuckDuckGo, Tavily, Exa, FireCrawl, Bing, BochaAI, XiYan, MySQL, Postgres)
- **Risultati**:
  - Grosse differenze tra server
  - MCP **NON** mostra miglioramento significativo vs function call
  - Effectiveness migliorabile ottimizzando parametri LLM-constructed
- **Posizionamento vs mio lavoro**: NON sicurezza. Utile come reference per "perché MCP è diffuso" ma fuori scope per la tesi security.

---

## F — Comparative protocol analysis (non solo MCP)

### 20. Security Analysis of Agentic AI Communication Protocols (Comparative)
**Yedidel Louck, Ariel Stulman, Amit Dvir** (Ariel University + Jerusalem College of Technology) — arXiv 2511.03841v1, Nov 2025

- **Obiettivo**: confronto empirico CORAL vs ACP vs A2A (NON MCP — protocolli agent-to-agent)
- **Metodologia**: 14-point vulnerability taxonomy → systematic assessment authentication/authorization/integrity/confidentiality/availability
- **Validazione**: empirical su CORAL implementation + SDK-based ACP + literature-based A2A
- **Risultati**:
  - CORAL: robust architecture ma implementation flaws (SSE gateway auth/authz)
  - ACP: architectural flexibility = vulnerability (optional JWS = high-impact integrity flaws)
  - Recommend hybrid: CORAL architecture + ACP mandatory per-message integrity
- **Posizionamento vs mio lavoro**: protocolli agent-to-agent, non MCP. Utile per inquadramento ma orthogonale.

---

## Tabella sinottica: chi ha fatto cosa empiricamente

| Paper | Server analizzati | Tool/Test | Anno | Metodo |
|-------|------------------:|----------:|------|--------|
| **Mio lavoro** | **69.104** (60.205 GH + 8.899 NPX) | tutti i tool esposti | 2026 | 7 framework + 3-stage pipeline |
| Toward Understanding (Xiaofan Li, Gao) | 67.057 (6 registri) | — | 2025 | qualitative + count |
| Mind Your Server (Zhao et al.) | 1.360 server, 12.230 tool | — | 2025 | MCP-SEC scanner |
| We Urgently Need Privilege (Zhihao Li) | 2.562 | — | 2025 | static analysis |
| MCP at First Glance (Hasan et al.) | 1.899 | — | 2025 | hybrid SAST + MCP scanner |
| AgentBound (Bühler et al.) | 296 | — | 2025 | policy generation |
| **⚠️ Compatibility at a Cost** (Yang, Bai, Lu) | **10 SDK ufficiali** (non server) | 1.265 rischi | 2026? | formal analysis SDK |
| Landscape (Hou et al.) | **0** (PoC artigianali) | 16 PoC | 2025 | PoC lab demos |
| MCPTox (Wang et al.) | 45 (live) | 353 tool, 1.312 test | 2025 | benchmark Tool Poisoning |
| MSB (Zhang et al.) | — | 400+ tool, 2.000 attacchi | 2025 | benchmark cross-agent |
| MCPSECBENCH (Yang et al.) | — | 17 attacchi, 3 provider | 2025 | benchmark cross-provider |
| MCPLIB (Guo et al.) | — | 31 attack methods | 2025 | benchmark library |
| MCPBench (Luo et al.) | ~10 | — | 2025 | performance (NON security) |

**Differenziatori del mio lavoro:**
1. **Scala assoluta** (69k server) — più grande di tutti gli empirical lavori MCP
2. **Profondità per-server** — non solo count, ma 7 categorie di vulnerability per server con VP/FP misurati
3. **Multi-framework consensus** — solo io combino 7 scanner diversi
4. **Validazione blind** — n=50/cat blind classification per misurare FP rate metodologico (~5%)
5. **NPX dataset integrato** — secondo dataset (8.899 npm packages) che nessun altro paper analizza

---

## Mapping minacce paper → categorie mie framework

Riferimento incrociato tra tassonomie dei paper e categorie del mio scan:

| Threat (paper) | Mio framework | Categoria |
|---------------|---------------|-----------|
| Tool Poisoning (Hou §5.1.4, MCPTox, ETDI) | mcp-shield + mcp-watch | hidden-instructions + tool-poisoning |
| Rug Pull (Hou §5.1.5, ETDI) | mcp-security-scan | rug-pull (X-03) |
| Typosquatting (Hou §5.1.1, ETDI) | — (out of scope per source code scan) | — |
| Command Injection (Hou §5.1.7) | mcp-guard + mcp-security-scan | command-injection-static/fuzzing + input-validation (X-02) |
| Indirect Prompt Injection (Hou §5.2.2) | mcp-scan | E001 + W015 |
| Sandbox Escape (Hou §5.3.2) | mcp-security-scan | dangerous-capabilities (X-01) |
| Credential Theft (Hou §5.3.1) | mcp-watch + mcp-guard | credential-leak + hardcoded-credential-static |
| Tool Chaining Abuse (Hou §5.3.3, Mind Your Server) | mcp-shield + mcp-scan | shadowing + W015 |
| Privilege Persistence (Hou §5.4.2) | mcp-check | tool_invocation/* |
| Parasitic Toolchain (Mind Your Server) | — (richiede execution trace) | — |
| Untrusted Content (NPX W015/W016/W017-W020) | mcp-scan | W015, W016, W017_npx-W020_npx |
| **PyTy** Silent Tool Injection (Compatibility at a Cost) | mcp-check | tool_invocation/schema_violation |
| **PyTn** Capability Assumption (Compatibility at a Cost) | mcp-check | tool_invocation/invalid_arguments |
| **PnTy** Timing DoS via ping (Compatibility at a Cost) | mcp-check | handshake/other_errors |

---

## File documenti correlati

- `analysisAllData/CROSS_FRAMEWORK_REPORT.md` — report aggregato cross-framework consensus
- `analysisAllData/0_tool_mcp_<framework>/README.md` — documentazione per ogni framework
- `THREAT_ANALYSIS_REPORT.md` — report tesi finale
- `CLAUDE.md` — contesto pipeline completo

**Ultima revisione**: 2026-05-18
