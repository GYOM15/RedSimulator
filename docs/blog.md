# RedSimulator — Building an AI-Powered Security Testing Pipeline

## Introduction

Web application security testing is traditionally a manual, time-consuming process that requires deep expertise. While tools like Burp Suite and OWASP ZAP have automated parts of the workflow, they still rely heavily on human judgment to interpret results and chain attack vectors.

RedSimulator explores a different approach: what if we combined multiple AI paradigms into a single pipeline that can autonomously scan, reason about vulnerabilities, generate attack payloads, and produce actionable reports?

The result is a modular pipeline that chains five distinct AI techniques — each solving a different part of the security testing problem.

## Architecture overview

The pipeline follows a sequential flow where each module's output feeds directly into the next:

```
Scanner (ReAct) → Expert System → VAE Generator → Executor → Reporter (RAG)
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

The engine currently implements three rules that demonstrate the chaining mechanism:
1. **SQL_INJECTION**: if a form exists and the target uses a SQL database → flag as HIGH
2. **XSS_REFLECTED**: if a POST endpoint exists and Content-Security-Policy is missing → flag as MEDIUM
3. **SQL_INJECTION_CRITICAL**: if a SQLi vector exists AND the endpoint requires no authentication → elevate to CRITICAL

Rule 3 is the interesting one — it depends on Rule 1 having already fired. This demonstrates how forward chaining can model escalation scenarios: a vulnerability that might be HIGH in isolation becomes CRITICAL when combined with weak access controls.

The output is a structured `AttackPlan` containing prioritized attack vectors with target endpoints, fields, and base payloads.

### 3. Variational Autoencoder — Payload mutation

Security testing benefits from payload diversity. A WAF (Web Application Firewall) might block `' OR 1=1--` but let through a semantically equivalent variant.

The generator uses a **character-level VAE** (Variational Autoencoder) built with PyTorch:
- **Encoder**: Embedding → GRU → latent space (16 dimensions)
- **Decoder**: latent vector → GRU → character probabilities

To generate variants, the model encodes a base payload into latent space, samples nearby points with controlled noise, and decodes them back into strings. Temperature controls the exploration-exploitation tradeoff: low temperature produces conservative mutations, high temperature produces more creative (but potentially broken) variants.

The model trains on a curated dataset of ~50 SQLi payloads in under a minute. The architecture is intentionally minimal — it's a foundation to build on with larger datasets and better quality filters.

### 4. Attack Executor

The executor takes the attack plan and generated payloads, then sends them against the target application. Currently, only SQL injection testing is implemented — it sends payloads to login endpoints and analyzes responses for indicators of success (SQL error messages, unexpected authentication, data leakage).

Rate limiting (200ms between requests) prevents overwhelming the target. Each result records the payload used, HTTP response status, a response snippet, and whether the attack succeeded.

### 5. Reporter + RAG Chatbot

The reporter generates a structured Markdown security report from the pipeline results. When a Claude API key is available, it uses the LLM for natural language generation; otherwise, it falls back to a template-based report with the data inserted.

The RAG (Retrieval-Augmented Generation) chatbot indexes the report into ChromaDB chunks and allows natural language queries about the findings. This turns a static report into an interactive knowledge base — useful for non-technical stakeholders who want to understand specific vulnerabilities without reading the full document.

## Frontend

The web interface is built with React and connects to the FastAPI backend via Server-Sent Events. It displays the pipeline execution in real time across 5 phases, with live logs, discovered endpoints, attack vectors, and results streaming in as they happen.

The UI includes severity distribution charts, attack success rates, and an integrated RAG chat for post-scan analysis — all in a dark theme optimized for security tooling.

## Current status and next steps

The scanner, orchestrator, API, and frontend are fully implemented. The expert system, VAE generator, executor, and reporter are functional scaffolds — they work end-to-end but need deeper implementation.

Immediate priorities:
- Expanding the expert system with more OWASP rules and chaining scenarios
- Adding XSS, IDOR, and path traversal to the executor
- Improving VAE output quality with larger datasets and better filtering
- Connecting ChromaDB in production mode for the RAG chatbot

## Lessons learned

**Fixtures-first development** was the best architectural decision. By defining Pydantic contracts and JSON fixtures upfront, every module could be developed and tested in isolation. The pipeline worked end-to-end with simulated data before any real scanning was implemented.

**Agent autonomy is a spectrum.** The ReAct agent works best when tools return raw facts and the agent decides what matters. Early versions had tools that made judgment calls (e.g., "this endpoint looks vulnerable") — removing those heuristics and letting the agent reason over raw data produced better results.

**Graceful degradation matters.** In a tool that depends on Docker, nmap, Playwright, and an LLM API, any component can be missing. Designing every layer with fallbacks (Docker nmap → local nmap → sockets, Claude API → template report) means the tool remains useful in any environment.
