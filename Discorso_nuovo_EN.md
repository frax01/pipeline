# How (In)secure Are MCP Servers?

## Slide 1 — Title *(~15s)*
Good morning everyone. My name is Francesco Martignoni, and I'm presenting my thesis: a large-scale security analysis of the Model Context Protocol ecosystem.

## Slide 2 — Model Context Protocol *(~55s)*
The Model Context Protocol is a standard introduced by Anthropic at the end of 2024. It connects a large language model (LLM) to external services — a file system, a database, an API, and so on. This expands what LLMs can do, but it also widens their attack surface.

The architecture has three components:
- the **host**, the application the user talks to, and the only one that communicates with the LLM;
- the **client**, one per server, with a dedicated session;
- and the **server**, the program that exposes the external capability, which can offer **three types of primitives**:
    - **tools**, actions the LLM decides to invoke autonomously during its reasoning;
    - **resources**, data attached to the conversation to provide more context;
    - and **prompts**, pre-defined shortcuts for the user.

There are two transport mechanisms: `stdio` for local servers, and `HTTP/SSE` for remote ones.

## Slide 3 — Execution Flow *(~60s)*
Let's look at an example of an execution flow, where a user asks to create a file called report.txt on the Desktop.
1. The first step is the user sending the prompt to the AI application.
2. The host passes the request to the LLM, together with the list of everything the servers make available — in this case filesystem and web. The model decides on its own which server and which tool to use: it picks write_file from the filesystem server, and builds its arguments — path, with the location of report.txt on the Desktop, and content, with the content of the report.
3. The host routes the call to the server through the dedicated client,
4. and the server executes the call, creating the file.

Notice that every server exposes three primitives — tools, resources and prompts — but the model can only invoke one of them: tools. Resources and prompts are called by the user.

The key point, security-wise as well, is that it is the model that chooses which tool to call and that produces its arguments.

## Slide 4 — Attacker Models & Threat Scenarios *(~55s)*
To formalize the analysis, I defined 3 attacker models and 9 threat scenarios; mapping one onto the other shows what kinds of security problems can arise.
- The first: the *malicious developer*, who publishes a server built specifically to harm the user. This happens through malicious code or backdoors — for example **tool poisoning**, where the description of a tool manipulates the LLM into performing a harmful action.
- Then the *malicious user*, who abuses unintentional weaknesses in a legitimate server, such as a developer mistake or insecure code — for example a **credential leak**: cleartext credentials in the source code.
- The third: the *external attacker*, who injects content into an external source that a server's tool retrieves and passes to the LLM, opening an indirect injection channel.

## Slide 5 — Goal & Research Questions *(~35s)*
The goal of this work is to study and measure how widespread vulnerabilities are across the entire MCP ecosystem, and to provide practical recommendations to prevent them.

From here, the three research questions, which are the common thread of the work:
- The first: how reliable are the existing security analysis frameworks for MCP?
- The second: which classes of vulnerabilities are the most widespread in the ecosystem?
- The third: which practical recommendations can reduce these risks?

## Slide 6 — Main Contributions *(~35s)*
The contribution of this study is threefold.
- First, we analyzed a large-scale dataset of more than 69K servers.
- Second, **SAMS**, a pipeline that combines seven security frameworks, with a subsequent post-processing phase and a final manual validation.
- Third, the empirical results, which show that most of the problems in the MCP ecosystem are classic programming mistakes, not new LLM-specific attacks — although those are widely present too.

## Slide 7 — SAMS: a Pipeline for MCP Security Analysis *(~35s)*
For the analysis I developed **SAMS**, a pipeline made of four phases.
- **Collection**, which gathers 69,104 unique servers.
- **Analysis**, which passes those servers to the seven frameworks, that analyze them with complementary techniques.
- **Post-processing**, which filters the millions of findings in three steps.
- And **Validation**, a manual review of the source code, which serves to measure how reliable the method is.

## Slide 8 — Data Collection *(~25s)*
In the Collection phase specifically, a program retrieves more than 148K servers from 18 different public sources. From there I normalize the URLs, compute a hash of the content, remove duplicates, and arrive at the final list of 69,104 unique servers.

## Slide 9 — Framework Selection *(~80s)*
The seven frameworks were selected starting from 26 tools proposed in the state of the art and, as you can see at the top of the table, I systematized them by analysis technique:
- static code analysis,
- LLM-based semantic analysis,
- protocol and tool testing,
- and dynamic fuzzing;

and then I selected seven of them for complementary and complete coverage.

An important point: I didn't just use them — in some cases I had to adapt or re-implement them.
For example *mcp-guard*, in its original version, made up vulnerabilities during fuzzing instead of actually testing for them, so I rewrote it with better logic; and *mcp-shield* used an LLM that I replaced with a local model, for cost, privacy and reproducibility.

And then a comparison with the state of the art: the closest work analyzes 67,000 servers, but only with Python tools.
All the other works study between 1,300 and 8,000 servers — a different order of magnitude compared to ours, which, on top of the 69K servers, uses seven analysis frameworks, four complementary techniques, and multiple languages.

## Slide 10 — Three-Stage Post-Processing *(~80s)*
Having laid out the full sequence of our pipeline: the seven scanners produce more than 3 million findings, but most of it is noise — it has to be filtered before it can be interpreted.
I do this in three post-processing stages.
1. **Stage 1** is a regular-expression filter that takes the 3 million findings and removes the obvious noise — for instance an `api_key` that is just a placeholder — and we drop to around 73,000 findings.
2. **Stage 2A** applies domain rules that look at the code being analyzed and at the identity of the server (name, language and file_path) — for example, a query built with an f-string is not a vulnerability if the whole job of that server is precisely to run SQL — and we get to around 23,000.
3. **Stage 2B** passes the ambiguous cases to a local LLM, which understands their meaning — for example a public Supabase anon key, which looks like a secret but is public by definition.
4. On top of that, mcp-scan did not take part in this stage of the analysis, since it already does this with its own logic, which gives us more than 4K findings.

In the end we have 27,958 high-confidence findings.

## Slide 11 — Manual Audit Validation: Framework Reliability (RQ1) *(~40s)*
To answer the first question, I validated the pipeline with a manual review of the source code, inspecting more than 1,500 findings.
The result is a precision of 64.8%: so the frameworks are useful, but still noisy.

The interesting part is that precision is uneven. The dynamic and semantic categories confirm between 80 and 100%, because they look at meaning. The static categories, on the other hand, evaluated with regular expressions, confirm far less, because they see neither the context nor the data flow.

## Slide 12 — Some misconfigurations and intentionally malicious examples *(~40s)*
To make these scenarios concrete, here are three examples.
- The first one is intentionally malicious: a poisoned tool description. A simple addition tool exposes an instruction saying to send all the emails to the attacker and not tell the user. The model may interpret that as part of the tool's behavior.
- The second one is a vulnerability: an honest tool, `execute_command`, that runs an arbitrary shell command — the capability is declared, but it is dangerous if it is granted to any caller, including a manipulated LLM.
- The third one, also a vulnerability, is a credential leak: a developer who publishes the server with a cleartext API key.

## Slide 13 — Vulnerability Distribution (RQ2) *(~35s)*
For the second question, on the distribution of vulnerabilities, I aggregated the 27K findings into the nine scenarios.
The most important thing here is to keep two different things separate.
The largest number, 15,436, is protocol non-compliance: these are robustness and quality issues — servers that do not follow the specification correctly and are poorly implemented.
The actual security vulnerabilities, instead, are 12,522, concentrated mainly in the first categories, from improper input validation to untrusted content.

## Slide 14 — Developer Recommendations (RQ3) *(~50s)*
For the third question, I grouped the recommendations into three key principles.

1. The first: treat every input as untrusted. So validate tool arguments in the code, never delegating that job to the LLM; and treat content retrieved from external sources as data, not as instructions.
2. The second: least privilege. Return only the data that is needed and not the whole environment, keep secrets out of the source code before publishing, and isolate dangerous capabilities instead of exposing them without restrictions.
3. The third: comply with the MCP protocol, which is the most widespread problem and — for those installing servers — only use trusted and verified ones.

The point is that almost all of these are classic security problems applied to a new surface.

## Slide 15 — Limitations *(~45s)*
A few limitations, important for interpreting the results and the work done.
1. The first concerns the dataset: I only analyze public, open-source servers, so private servers are left out; and it is a snapshot of a fast-moving ecosystem, so I don't observe how servers change over time.
2. The second is about interpretation: protocol non-compliance and exploitable vulnerabilities must be read separately.
3. The third concerns precision — that is, how many of the reported findings are real — and not recall, because there is no official benchmark of MCP vulnerabilities; furthermore, precision is estimated on a sample rather than by manually validating everything, and part of the classification goes through an LLM, which can introduce uncertainty.

## Slide 16 — Conclusions & Future Works *(~45s)*
In conclusion, three key messages.
- MCP servers expose a broad and rapidly growing attack surface, with hundreds or thousands of new servers appearing every month.
- Most of the problems are classic software security mistakes, not LLM-specific attacks — although those are very much present.
- And analysis frameworks do help, but they need to be validated and analyzed to be made reliable.

As future work I propose:
- a proxy-style LLM fuzzing approach, to test real exploitability at runtime, capturing tool inputs and outputs that static analysis cannot detect.

## Slide 17 — Closing *(~10s)*
Thank you for your attention. I'm happy to take any questions.

## Slide 18 — References
