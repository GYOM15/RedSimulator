# RedSimulator -- Building an AI-Powered Security Testing Pipeline

## Introduction

Web application security testing is traditionally a manual, time-consuming process that requires deep expertise. While tools like Burp Suite and OWASP ZAP have automated parts of the workflow, they still rely heavily on human judgment to interpret results and chain attack vectors.

RedSimulator explores a different approach: what if we combined multiple AI paradigms into a single pipeline that can autonomously scan, reason about vulnerabilities, generate attack payloads, validate findings, and produce actionable reports?

The result is a modular pipeline that chains six distinct stages -- each solving a different part of the security testing problem -- supported by dedicated infrastructure for authentication, traffic interception, and observability.

## Architecture overview

The pipeline follows a sequential flow where each module's output feeds directly into the next:

```
Scanner (ReAct) -> Passive Scanning -> Expert System -> Payload Generator -> Executor -> Validator -> Reporter (RAG)
```

Every module communicates through strict **Pydantic models**, which act as typed contracts. This means each component can be developed, tested, and improved independently -- a module only needs to produce the right data shape.

The system supports two modes:
- **Fixtures mode**: runs the full pipeline with simulated data, no external dependencies needed
- **Live mode**: targets a real application (OWASP Juice Shop) running in Docker

Three cross-cutting infrastructure modules support the pipeline:
- **Auth** -- manages authentication state across all HTTP interactions
- **Proxy** -- captures and replays live traffic via a MITM proxy
- **Infra** -- provides AOP decorators, structured logging, and configuration management

## AI techniques

### 1. ReAct Agent -- Autonomous reconnaissance

The scanner is built around a **ReAct (Reasoning + Acting)** agent powered by Claude via LangGraph. Unlike a traditional scanner that runs a fixed sequence of checks, the agent decides on its own which tools to use and in what order.

It has access to 9 specialized tools: port scanning, endpoint discovery, header analysis, form detection, directory brute-forcing, technology fingerprinting, custom HTTP probing, DNS enumeration, and API spec discovery (OpenAPI/Swagger/GraphQL). Each tool is designed to return raw facts -- the agent interprets them and decides what to investigate next.

Key design decisions:
- **Self-evaluation loop**: after the agent submits its scan report, an evaluation step checks for completeness. If gaps are found, the agent is relaunched with targeted feedback (max 2 iterations)
- **Persistent memory**: scan results are stored per target, so subsequent scans can detect changes (new endpoints, ports, risk score deltas)
- **Graceful degradation**: every tool has multiple backends. Port scanning tries nmap via Docker, then local nmap, then falls back to raw sockets. This ensures the scanner works in any environment
- **Dynamic analysis**: Playwright is used to render SPAs and discover forms/routes that only exist after JavaScript execution -- critical for modern frameworks like Angular
- **API spec parsing**: the `api_spec_scanner` tool discovers and parses OpenAPI/Swagger definitions and GraphQL schemas, extracting all documented endpoints, parameters, and authentication requirements automatically

### 2. Passive Scanning -- Non-intrusive security checks

Between the scanner and the expert system sits a **passive scanning** stage that analyzes the HTTP responses already collected during reconnaissance -- no additional requests are sent.

Six checks run in parallel:
- **Headers** -- detects missing security headers (HSTS, X-Frame-Options, Content-Security-Policy, X-Content-Type-Options, Permissions-Policy)
- **Cookies** -- analyzes cookie attributes (Secure, HttpOnly, SameSite) and flags insecure configurations
- **CORS** -- identifies overly permissive CORS policies (wildcard origins, credentials exposure)
- **Information disclosure** -- detects server banners, verbose error pages, and stack traces in responses
- **Transport security** -- checks HTTPS enforcement and mixed content issues
- **Sensitive URLs** -- flags sensitive data (tokens, credentials, PII) appearing in URL query strings

Every finding carries a **CWE identifier** (e.g., CWE-614 for missing Secure flag, CWE-209 for information exposure through error messages), providing a direct link to the MITRE weakness catalog for remediation guidance.

Passive findings are injected as facts into the expert system, where they can trigger additional rules and influence attack plan prioritization.

### 3. Expert System -- Forward chaining over OWASP rules

The expert system implements a classic **forward-chaining inference engine**. It converts the scan results and passive findings into a set of facts, then iteratively applies rules until no more can fire.

The engine implements **20 rules** organized across three categories:

**Core vulnerability rules** (`rules.py` -- 11 rules):
- SQL_INJECTION, XSS_REFLECTED, SQL_INJECTION_CRITICAL, IDOR, PATH_TRAVERSAL, AUTH_BYPASS, INFO_DISCLOSURE, CSRF, OPEN_REDIRECT, COMMAND_INJECTION, BROKEN_AUTH

**Header/configuration rules** (`rules_header.py` -- 4 rules):
- MISSING_HSTS, MISSING_XFRAME, INSECURE_COOKIES, SENSITIVE_DATA_EXPOSURE

**Attack chaining rules** (`rules_chaining.py` -- 5 rules):
- CHAIN_BYPASS_EXFIL, CHAIN_XSS_SESSION, CHAIN_IDOR_INFO, XSS_CRITICAL, MULTI_VULN_CRITICAL

The chaining rules demonstrate the real power of forward chaining. For example, CHAIN_BYPASS_EXFIL fires only when both an AUTH_BYPASS and a SQL_INJECTION vector have already been identified -- modeling a realistic two-step attack where an attacker bypasses authentication and then exfiltrates data through injection. MULTI_VULN_CRITICAL elevates the overall risk when multiple vulnerability types are detected on the same target.

Passive findings (missing HSTS, insecure cookies, etc.) are converted into facts that the header/configuration rules consume directly. This means the expert system reasons over the full picture -- active scan results and passive observations combined.

An **LLM analyst second pass** (`llm_analyst.py`) reviews the expert system's output using Claude, adding context-aware analysis that pure rules cannot capture -- such as identifying subtle attack chains or adjusting severity based on the target's technology stack.

On the Juice Shop fixture data, 17 of the 20 rules fire, producing 14 prioritized attack vectors.

The output is a structured `AttackPlan` containing prioritized attack vectors with target endpoints, fields, and base payloads.

### 4. LLM-based Generator with Payload Intelligence -- Smart payload mutation

Security testing benefits from payload diversity. A WAF (Web Application Firewall) might block `' OR 1=1--` but let through a semantically equivalent variant.

The generator uses a **dual-strategy approach**:
- **LLM mutator**: leverages Claude to generate semantically equivalent payload variants with context-aware mutations
- **Offline mutator**: deterministic, rule-based transformations (encoding tricks, whitespace manipulation, comment injection, case variations) that work without an API key

When an LLM API key is available, the generator produces creative, context-aware variants. Without one, the offline fallback applies deterministic mutation strategies drawn from curated payload datasets. Both strategies filter duplicates and the original payload from the output.

The offline mutator covers SQLi, XSS, IDOR, and path traversal attack types, each with type-specific mutation rules derived from real-world bypass techniques.

**Payload intelligence system** (`payload_db.py`): Beyond mutation, the generator maintains an annotated payload database with 1149 payloads across 8 attack categories, stored as `.jsonl` files with rich metadata:
- **WAF-aware selection**: the system detects WAFs from HTTP response headers (Cloudflare, AWS WAF, ModSecurity, etc.) and filters payloads to those known to bypass the detected WAF
- **DB-aware selection**: database engine inference from error messages and headers selects payloads targeting the specific SQL dialect (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
- **Feedback loop** (`feedback.py`): executor results feed back into the generator to prioritize successful payload families and deprioritize patterns that were blocked, improving selection accuracy over the course of a scan

### 5. Attack Executor -- Plugin-based attack engine

The executor takes the attack plan and generated payloads, then runs them against the target application through a **plugin architecture** with 9 specialized attack handlers:

| Handler | Techniques |
|---------|-----------|
| **SQL injection** | Error-based detection, auth bypass, UNION extraction |
| **XSS** | Reflected, stored, partial sanitization bypass |
| **IDOR** | ID enumeration, response comparison |
| **Path traversal** | Encoding tricks, OS-specific variants |
| **Auth bypass** | Direct access, method tampering, header manipulation, default credentials |
| **Info disclosure** | Header probing, error triggering, sensitive data detection, directory listing |
| **Command injection** | Separator-based, blind time-based, output-based |
| **CSRF** | Token absence/validation, SameSite policy, referer checking |
| **Open redirect** | Location header analysis, JavaScript redirect detection |

Each handler inherits from an abstract `AttackHandler` base class, making it straightforward to add new attack types. A `SessionManager` handles cookies and authentication state across requests, integrating with the auth framework for automatic re-authentication. An LLM-based `ResponseAnalyzer` provides intelligent analysis of attack responses when pattern matching is ambiguous.

Rate limiting (200ms between requests) prevents overwhelming the target. Each result records the payload used, HTTP response status, a response snippet, and whether the attack succeeded.

### 6. False Positive Validation -- Multi-strategy confidence scoring

Raw executor results inevitably include false positives. The validator module addresses this with four complementary strategies:

- **Differential analysis** (`differential.py`): sends the same request with and without the attack payload, comparing responses to determine if the payload actually caused a change in behavior. If the responses are identical, the finding is likely a false positive
- **Multi-payload validation** (`multi_payload.py`): tests the same vulnerability with multiple semantically equivalent payloads. A real vulnerability should be triggered by several variants, not just one specific string
- **LLM analysis** (`llm_analysis.py`): for ambiguous cases where pattern matching is insufficient, Claude analyzes the response content, HTTP headers, and behavioral signals to make a judgment call
- **Timing-based validation** (`timing.py`): for blind vulnerabilities (blind SQLi, blind command injection), measures response time differences to confirm the payload actually executed on the server

Each finding receives a **confidence score** computed from the strategies that evaluated it. Findings below a configurable threshold are automatically downgraded from "confirmed" to "potential," preventing false alarms from reaching the final report. This multi-layered approach catches FPs that any single method would miss.

### 7. Reporter + RAG Chatbot

The reporter generates a structured Markdown security report from the pipeline results. When a Claude API key is available, it uses the LLM for natural language generation; otherwise, it falls back to a template-based report with the data inserted. Reports can be **exported to PDF** via weasyprint with professional styling.

The RAG (Retrieval-Augmented Generation) chatbot indexes the report and allows natural language queries about the findings. This turns a static report into an interactive knowledge base -- useful for non-technical stakeholders who want to understand specific vulnerabilities without reading the full document.

The RAG system is built from five custom components:

- **Smart hierarchical chunking** (`rag/chunker.py`): recursively splits Markdown reports by heading level (H1 -> H2 -> H3 -> paragraph -> sentence) and enriches each chunk with extracted metadata -- severity levels, attack type keywords, vulnerability IDs (VEC-001, etc.), and endpoint paths. This metadata powers filtered search later in the pipeline.

- **FAISS vector store** (`rag/vector_store.py`): uses `IndexFlatIP` with L2-normalized embeddings to perform exact cosine-similarity search. This is appropriate for the small datasets typical of security reports (hundreds of chunks, not millions). A pure-Python fallback computes cosine similarity directly when FAISS is not installed, so the pipeline remains functional without native extensions.

- **fastembed embeddings** (`rag/embeddings.py`): uses the BAAI/bge-small-en-v1.5 model (384-dimensional, ONNX runtime, ~33 MB download, no PyTorch needed) for high-quality semantic embeddings. When fastembed is unavailable, falls back to a zero-dependency TF-IDF vectorizer built from scratch -- vocabulary and IDF scores are computed from the indexed documents.

- **NetworkX knowledge graph** (`rag/knowledge_graph.py`): builds a directed graph from scan results, attack plan, and execution results. The graph contains eight node types (vulnerability, endpoint, technology, header, form, remediation, owasp_category, result) connected by six relationship types (TARGETS, EXPLOITS, CHAINS_WITH, FIXED_BY, RUNS_ON, AFFECTS). This enables structured queries that vector search alone cannot answer -- for example, "What vulnerabilities affect /rest/user/login?" returns precise results by traversing graph edges rather than relying on text similarity. The graph also models attack chains, OWASP category mappings, and prioritized remediations.

- **Hybrid retriever** (`rag/retriever.py`): combines vector search with knowledge graph context. Intent detection analyzes each question to determine which graph queries to run (endpoint lookup, severity filter, attack type search, remediation lookup, chain traversal). Vector results and graph context are merged, deduplicated, and ranked by a unified relevance score.

The system operates at **three degradation levels**:
- **Full mode**: FAISS + knowledge graph + Claude LLM -- semantic search augmented with structured graph context, answers generated by the LLM
- **Partial mode**: FAISS only -- vector similarity search without graph augmentation (when scan/plan/results data is not provided)
- **Degraded mode**: TF-IDF keyword fallback -- when neither FAISS nor fastembed is installed, falls back to term-frequency scoring with security-domain boost terms

## Auth framework

Security tools that cannot authenticate are limited to testing public endpoints. The auth framework (`src/auth/`) provides transparent authentication across the entire pipeline:

Four providers cover the most common web authentication schemes:
- **Basic** -- HTTP Basic authentication (username/password in Authorization header)
- **Cookie/CSRF** -- form-based login with automatic CSRF token extraction and cookie management
- **Bearer/JWT** -- token-based auth with automatic refresh on expiry
- **OAuth2** -- authorization code and client credentials flows

The auth manager auto-detects which scheme the target uses by analyzing login page structure and response headers. When a session expires mid-scan, the manager transparently re-authenticates without interrupting the pipeline. All auth state is shared with the Executor's SessionManager, ensuring that attack payloads are sent with valid session credentials.

## MITM Proxy

The proxy module (`src/proxy/`) provides a man-in-the-middle proxy built on mitmproxy that integrates directly with the pipeline:

- **Traffic capture**: intercepts all HTTP/HTTPS traffic between the browser and the target, storing flows in a SQLite-backed FlowStore
- **Request replay**: captured flows can be replayed with payload modifications, enabling a "capture once, test many" workflow
- **Feed adapter**: converts captured proxy flows into scanner-compatible input, so manual browsing sessions can seed the automated pipeline
- **CA certificate management**: generates and manages the CA certificate needed for HTTPS interception

The proxy is an optional component (installed via `pip install .[proxy]`). When active, the frontend's ProxyView component displays captured traffic in real time.

## Infrastructure -- AOP and observability

Production-quality tooling needs more than just features -- it needs observability and resilience. The `src/infra/` module provides cross-cutting concerns through **Aspect-Oriented Programming** decorators:

- `@logged`: automatic entry/exit logging with arguments and return values
- `@retry`: configurable retry with exponential backoff for transient failures
- `@timed`: execution time measurement for performance profiling
- `@safe`: exception catching with structured error reporting

Configuration is managed through **Pydantic Settings**, providing type-safe, environment-variable-backed configuration with validation. All logging is structured (both text and JSON formats), and the codebase has zero `print()` calls -- everything flows through the structured logging system.

A typed exception hierarchy ensures consistent error handling across all modules, and CI (GitHub Actions) enforces code quality with ruff linting, mypy type checking, and pytest on every push.

## Frontend

The web interface is built with React and connects to the FastAPI backend via Server-Sent Events. It displays the pipeline execution in real time across 6 phases, with live logs, discovered endpoints, passive findings, attack vectors, validation results, and proxy traffic streaming in as they happen.

The frontend was decomposed into **15+ component files** including specialized views: ScannerView, ExpertView, AttackView, ReportView, ChatView, ProxyView, SummaryView, VAEView, and supporting components (Charts, Markdown, ScrollBox, Sidebar). A custom `usePipeline.js` hook manages SSE state, and theme constants live in `styles/theme.js`.

The UI includes severity distribution charts, attack success rates, and an integrated RAG chat for post-scan analysis -- all in a dark theme optimized for security tooling.

## Testing

The test suite includes **145+ tests** organized into three tiers:

- **Unit/integration tests** (`tests/test_*.py`): cover models, expert system (42 tests), executor (23 tests), generator, infrastructure (44 tests including AOP decorators), and end-to-end pipeline flows
- **Battle tests** (`tests/battle/`): run the full pipeline against live Docker targets (DVWA, WebGoat) to measure real-world detection rates. A weekly GitHub Actions workflow (`battle.yml`) executes these automatically
- **Regression tracker** (`tests/regression/tracker.py`): records detection rate snapshots per target and flags regressions when the detection rate drops below baseline, preventing silent quality degradation

## Current status

All six pipeline stages and all infrastructure modules are fully implemented and functional end-to-end:

- **Scanner**: 9-tool ReAct agent with self-evaluation, API spec discovery, and persistent memory
- **Passive Scanning**: 6 checks with CWE references, findings feed into expert system
- **Expert System**: 20 rules across 3 categories with LLM analyst second pass
- **Generator**: LLM-based mutation with offline fallback + payload intelligence (1149 annotated payloads, WAF/DB-aware selection, feedback loop)
- **Executor**: 9 attack handlers with plugin architecture, session management, and LLM response analysis
- **Validator**: 4 strategies (differential, multi-payload, LLM, timing) with confidence scoring and FP auto-downgrade
- **Reporter**: Template-based and LLM-generated reports with PDF export and hybrid RAG chatbot (FAISS + knowledge graph)
- **Auth**: 4 providers with auto-detection and transparent re-auth
- **Proxy**: MITM traffic capture, SQLite flow storage, replay, and pipeline feed adapter

The infrastructure layer (AOP decorators, structured logging, Pydantic Settings, CI pipeline, Docker with healthchecks, battle testing, regression tracking) provides production-grade observability and resilience across all modules.

## Lessons learned

**Fixtures-first development** was the best architectural decision. By defining Pydantic contracts and JSON fixtures upfront, every module could be developed and tested in isolation. The pipeline worked end-to-end with simulated data before any real scanning was implemented.

**Agent autonomy is a spectrum.** The ReAct agent works best when tools return raw facts and the agent decides what matters. Early versions had tools that made judgment calls (e.g., "this endpoint looks vulnerable") -- removing those heuristics and letting the agent reason over raw data produced better results.

**Graceful degradation matters.** In a tool that depends on Docker, nmap, Playwright, and an LLM API, any component can be missing. Designing every layer with fallbacks (Docker nmap -> local nmap -> sockets, Claude API -> template report, LLM mutator -> offline mutator, FAISS -> TF-IDF) means the tool remains useful in any environment.

**Plugin architectures pay off early.** The executor's abstract `AttackHandler` base class made adding new attack types mechanical -- each handler is self-contained, testable, and follows the same interface. Going from 1 handler (SQLi) to 9 took a fraction of the time it took to build the first one.

**Structured logging over print().** Replacing all `print()` calls with structured logging (text + JSON) and AOP decorators (`@logged`, `@timed`) transformed debugging from guesswork into data. When a 20-rule expert system fires, being able to trace exactly which rules fired and why -- with timing data -- is essential.

**LLM as a second pair of eyes.** Using an LLM analyst as a second pass over the expert system's output catches patterns that pure rules miss. Rules are fast and deterministic; the LLM adds contextual reasoning. The combination is stronger than either approach alone.

**Knowledge graphs complement vector search.** Vector similarity excels at finding semantically related text, but it cannot answer structural questions like "What vulnerabilities chain together on this endpoint?" or "Which remediations cover the most critical findings?" Adding a NetworkX knowledge graph alongside FAISS gave the RAG chatbot the ability to traverse typed relationships (TARGETS, CHAINS_WITH, FIXED_BY) and return precise, structured answers that pure embedding similarity would miss. The hybrid retriever merges both result streams with intent detection, so the user gets semantic relevance and structural precision in a single query.

**False positive validation is not optional.** Early versions of the pipeline produced results that looked impressive on paper but included too many FPs. Adding the validator stage with four complementary strategies (differential, multi-payload, LLM, timing) and confidence scoring dramatically improved result quality. The key insight: no single validation method catches everything. Differential analysis misses blind vulnerabilities. Timing-based checks are useless for reflected XSS. The multi-strategy approach with confidence scoring lets each method contribute its strength while the aggregate score filters noise.

**Proxy integration unlocks manual+automated workflows.** Building the MITM proxy with a feed adapter that converts captured traffic into scanner input bridged the gap between manual exploration and automated testing. Testers can browse the target naturally, then feed their session into the pipeline for automated analysis -- combining human intuition with machine thoroughness.
