# RedSimulator — Building an AI-Powered Security Testing Pipeline

## Introduction

Web application security testing is traditionally a manual, time-consuming process that requires deep expertise. While tools like Burp Suite and OWASP ZAP have automated parts of the workflow, they still rely heavily on human judgment to interpret results and chain attack vectors.

RedSimulator explores a different approach: what if we combined multiple AI paradigms into a single pipeline that can autonomously scan, reason about vulnerabilities, generate attack payloads, and produce actionable reports?

The result is a modular pipeline that chains five distinct AI techniques — each solving a different part of the security testing problem.

## Architecture overview

The pipeline follows a sequential flow where each module's output feeds directly into the next:

```
Scanner (ReAct) → Expert System → Payload Generator → Executor → Reporter (RAG)
```

Every module communicates through strict **Pydantic models**, which act as typed contracts. This means each component can be developed, tested, and improved independently — a module only needs to produce the right data shape.

The system supports two modes:
- **Fixtures mode**: runs the full pipeline with simulated data, no external dependencies needed
- **Live mode**: targets a real application (OWASP Juice Shop) running in Docker

## AI techniques

### 1. ReAct Agent — Autonomous reconnaissance

The scanner is built around a **ReAct (Reasoning + Acting)** agent powered by Claude via LangGraph. Unlike a traditional scanner that runs a fixed sequence of checks, the agent decides on its own which tools to use and in what order.

It has access to 8 specialized tools: port scanning, endpoint discovery, header analysis, form detection, directory brute-forcing, technology fingerprinting, custom HTTP probing, and DNS enumeration. Each tool is designed to return raw facts — the agent interprets them and decides what to investigate next.

Key design decisions:
- **Self-evaluation loop**: after the agent submits its scan report, an evaluation step checks for completeness. If gaps are found, the agent is relaunched with targeted feedback (max 2 iterations)
- **Persistent memory**: scan results are stored per target, so subsequent scans can detect changes (new endpoints, ports, risk score deltas)
- **Graceful degradation**: every tool has multiple backends. Port scanning tries nmap via Docker, then local nmap, then falls back to raw sockets. This ensures the scanner works in any environment
- **Dynamic analysis**: Playwright is used to render SPAs and discover forms/routes that only exist after JavaScript execution — critical for modern frameworks like Angular

### 2. Expert System — Forward chaining over OWASP rules

The expert system implements a classic **forward-chaining inference engine**. It converts the scan results into a set of facts, then iteratively applies rules until no more can fire.

The engine implements **20 rules** organized across three categories:

**Core vulnerability rules** (`rules.py` — 11 rules):
- SQL_INJECTION, XSS_REFLECTED, SQL_INJECTION_CRITICAL, IDOR, PATH_TRAVERSAL, AUTH_BYPASS, INFO_DISCLOSURE, CSRF, OPEN_REDIRECT, COMMAND_INJECTION, BROKEN_AUTH

**Header/configuration rules** (`rules_header.py` — 4 rules):
- MISSING_HSTS, MISSING_XFRAME, INSECURE_COOKIES, SENSITIVE_DATA_EXPOSURE

**Attack chaining rules** (`rules_chaining.py` — 5 rules):
- CHAIN_BYPASS_EXFIL, CHAIN_XSS_SESSION, CHAIN_IDOR_INFO, XSS_CRITICAL, MULTI_VULN_CRITICAL

The chaining rules demonstrate the real power of forward chaining. For example, CHAIN_BYPASS_EXFIL fires only when both an AUTH_BYPASS and a SQL_INJECTION vector have already been identified — modeling a realistic two-step attack where an attacker bypasses authentication and then exfiltrates data through injection. MULTI_VULN_CRITICAL elevates the overall risk when multiple vulnerability types are detected on the same target.

An **LLM analyst second pass** (`llm_analyst.py`) reviews the expert system's output using Claude, adding context-aware analysis that pure rules cannot capture — such as identifying subtle attack chains or adjusting severity based on the target's technology stack.

On the Juice Shop fixture data, 17 of the 20 rules fire, producing 14 prioritized attack vectors.

The output is a structured `AttackPlan` containing prioritized attack vectors with target endpoints, fields, and base payloads.

### 3. LLM-based Generator with Offline Fallback — Payload mutation

Security testing benefits from payload diversity. A WAF (Web Application Firewall) might block `' OR 1=1--` but let through a semantically equivalent variant.

The generator uses a **dual-strategy approach**:
- **LLM mutator**: leverages Claude to generate semantically equivalent payload variants with context-aware mutations
- **Offline mutator**: deterministic, rule-based transformations (encoding tricks, whitespace manipulation, comment injection, case variations) that work without an API key

When an LLM API key is available, the generator produces creative, context-aware variants. Without one, the offline fallback applies deterministic mutation strategies drawn from curated payload datasets. Both strategies filter duplicates and the original payload from the output.

The offline mutator covers SQLi, XSS, IDOR, and path traversal attack types, each with type-specific mutation rules derived from real-world bypass techniques.

### 4. Attack Executor — Plugin-based attack engine

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

Each handler inherits from an abstract `AttackHandler` base class, making it straightforward to add new attack types. A `SessionManager` handles cookies and authentication state across requests, and an LLM-based `ResponseAnalyzer` provides intelligent analysis of attack responses when pattern matching is ambiguous.

Rate limiting (200ms between requests) prevents overwhelming the target. Each result records the payload used, HTTP response status, a response snippet, and whether the attack succeeded.

### 5. Reporter + RAG Chatbot

The reporter generates a structured Markdown security report from the pipeline results. When a Claude API key is available, it uses the LLM for natural language generation; otherwise, it falls back to a template-based report with the data inserted.

The RAG (Retrieval-Augmented Generation) chatbot indexes the report into ChromaDB chunks and allows natural language queries about the findings. This turns a static report into an interactive knowledge base — useful for non-technical stakeholders who want to understand specific vulnerabilities without reading the full document.

## Infrastructure — AOP and observability

Production-quality tooling needs more than just features — it needs observability and resilience. The `src/infra/` module provides cross-cutting concerns through **Aspect-Oriented Programming** decorators:

- `@logged`: automatic entry/exit logging with arguments and return values
- `@retry`: configurable retry with exponential backoff for transient failures
- `@timed`: execution time measurement for performance profiling
- `@safe`: exception catching with structured error reporting

Configuration is managed through **Pydantic Settings**, providing type-safe, environment-variable-backed configuration with validation. All logging is structured (both text and JSON formats), and the codebase has zero `print()` calls — everything flows through the structured logging system.

A typed exception hierarchy ensures consistent error handling across all modules, and CI (GitHub Actions) enforces code quality with ruff linting, mypy type checking, and pytest on every push.

## Frontend

The web interface is built with React and connects to the FastAPI backend via Server-Sent Events. It displays the pipeline execution in real time across 5 phases, with live logs, discovered endpoints, attack vectors, and results streaming in as they happen.

The frontend was decomposed from a monolithic 702-line `App.jsx` into **15 files**: 11 component files in `components/`, a custom `usePipeline.js` hook, and theme constants in `styles/theme.js`. This separation makes each component independently testable and keeps the codebase maintainable.

The UI includes severity distribution charts, attack success rates, and an integrated RAG chat for post-scan analysis — all in a dark theme optimized for security tooling.

## Current status

All five pipeline modules are fully implemented and functional end-to-end:

- **Scanner**: 8-tool ReAct agent with self-evaluation and persistent memory
- **Expert System**: 20 rules across 3 categories with LLM analyst second pass
- **Generator**: LLM-based mutation with deterministic offline fallback
- **Executor**: 9 attack handlers with plugin architecture, session management, and LLM response analysis
- **Reporter**: Template-based and LLM-generated reports with RAG chatbot

The infrastructure layer (AOP decorators, structured logging, Pydantic Settings, CI pipeline, Docker with healthchecks) provides production-grade observability and resilience across all modules.

## Lessons learned

**Fixtures-first development** was the best architectural decision. By defining Pydantic contracts and JSON fixtures upfront, every module could be developed and tested in isolation. The pipeline worked end-to-end with simulated data before any real scanning was implemented.

**Agent autonomy is a spectrum.** The ReAct agent works best when tools return raw facts and the agent decides what matters. Early versions had tools that made judgment calls (e.g., "this endpoint looks vulnerable") — removing those heuristics and letting the agent reason over raw data produced better results.

**Graceful degradation matters.** In a tool that depends on Docker, nmap, Playwright, and an LLM API, any component can be missing. Designing every layer with fallbacks (Docker nmap → local nmap → sockets, Claude API → template report, LLM mutator → offline mutator) means the tool remains useful in any environment.

**Plugin architectures pay off early.** The executor's abstract `AttackHandler` base class made adding new attack types mechanical — each handler is self-contained, testable, and follows the same interface. Going from 1 handler (SQLi) to 9 took a fraction of the time it took to build the first one.

**Structured logging over print().** Replacing all `print()` calls with structured logging (text + JSON) and AOP decorators (`@logged`, `@timed`) transformed debugging from guesswork into data. When a 20-rule expert system fires, being able to trace exactly which rules fired and why — with timing data — is essential.

**LLM as a second pair of eyes.** Using an LLM analyst as a second pass over the expert system's output catches patterns that pure rules miss. Rules are fast and deterministic; the LLM adds contextual reasoning. The combination is stronger than either approach alone.
