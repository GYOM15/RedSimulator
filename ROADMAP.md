# RedSimulator -- ROADMAP

## How to run the project

### Prerequisites

- Python >= 3.11
- (Optional) Docker -- for Juice Shop and ChromaDB
- (Optional) Anthropic API key -- for LLM modules
- (Optional) nmap -- for advanced port scanning

### Installation

```bash
cd redsimulator
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Install Chromium for Playwright (dynamic SPA analysis)
python3 -m playwright install chromium

# Optional dependencies
pip install -e ".[proxy]"   # MITM proxy support (mitmproxy)
pip install -e ".[pdf]"     # PDF report export (weasyprint)
```

### Launch -- fixtures mode (no external dependencies)

```bash
# Full pipeline with simulated data
python3 -m src.orchestrator --fixtures

# Individual modules
python3 -m src.expert           # Expert system only
python3 -m src.generator        # Generator only
python3 -m src.executor         # Executor only
python3 -m src.reporter         # Reporter + RAG only
python3 -m src.scanner --fixtures  # Scanner with fixture

# Tests
pytest tests/ -v

# Battle tests (requires Docker targets)
pytest tests/battle/ -v
```

### Launch -- live mode (with Juice Shop)

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env -> ANTHROPIC_API_KEY=sk-ant-api03-...

# 2. Start Docker services
docker-compose up -d
# -> Juice Shop at http://localhost:3000
# -> ChromaDB at http://localhost:8000

# 3. Scanner only (no API key = sequential fallback)
python3 -m src.scanner

# 4. Full live pipeline
python3 -m src.orchestrator --target http://localhost:3000
```

---

## Completed modules

### 1. Scanner (`src/scanner/`) -- COMPLETE

| File | Responsibility | Status |
|------|---------------|--------|
| `agent.py` | ReAct agent with self-evaluation and retry loop | Done |
| `tools.py` | 9 tools: port_scan, endpoint_discovery, header_checker, form_analyzer, probe_endpoint, tech_detector, directory_bruteforce, dns_enum, api_spec_scanner | Done |
| `api_specs/` | OpenAPI/Swagger/GraphQL spec discovery and parsing | Done |
| `http_utils.py` | Secure HTTP requests + error formatting | Done |
| `crawlers.py` | Path discovery (HTML + JS bundles + Playwright) | Done |
| `form_parsing.py` | Form analysis (static + dynamic Playwright) | Done |
| `tech_detector.py` | Technology and version detection (headers, HTML, JS, package.json, endpoints) | Done |
| `browser.py` | Playwright singleton (headless Chromium) | Done |
| `memory.py` | Persistent scan history per target | Done |

**Scanner capabilities:**
- 9 autonomous tools for the agent + category-based wordlists
- API spec discovery (OpenAPI/Swagger/GraphQL)
- Self-evaluation of report with retry loop (max 2 iterations)
- Factual summaries without hardcoded heuristics
- Response content analysis (secrets, tokens, source code detection)
- Parameter extraction (path params, query params, JSON keys)
- Port scanning (nmap Docker / nmap local / socket fallback)
- Multi-source crawling (HTML + JS + Playwright + wordlists)
- Technology detection with versions
- Cookie analysis (Secure, HttpOnly, SameSite) + CORS

### 2. Passive Scanning (`src/passive/`) -- COMPLETE

- [x] 6 passive checks: headers, cookies, CORS, information disclosure, transport security, sensitive URLs
- [x] CWE references on all findings
- [x] Passive findings injected as facts into the expert system
- [x] Non-intrusive -- analyzes existing responses only, no additional requests

### 3. Expert System (`src/expert/`) -- COMPLETE

- [x] 20 rules across 3 categories
- [x] Core vulnerability rules (rules.py -- 11 rules): SQLi, XSS, IDOR, PATH_TRAVERSAL, AUTH_BYPASS, INFO_DISCLOSURE, CSRF, OPEN_REDIRECT, COMMAND_INJECTION, BROKEN_AUTH
- [x] Header/config rules (rules_header.py -- 4 rules): MISSING_HSTS, MISSING_XFRAME, INSECURE_COOKIES, SENSITIVE_DATA_EXPOSURE
- [x] Chaining rules (rules_chaining.py -- 5 rules): CHAIN_BYPASS_EXFIL, CHAIN_XSS_SESSION, CHAIN_IDOR_INFO, XSS_CRITICAL, MULTI_VULN_CRITICAL
- [x] LLM analyst second pass (llm_analyst.py)
- [x] Passive findings consumed as facts
- [x] Vulnerability correlation (attack chains)
- [x] 17/20 rules fire on Juice Shop fixture -> 14 attack vectors

### 4. Generator (`src/generator/`) -- COMPLETE

- [x] LLM mutation via Claude API (llm_mutator.py)
- [x] Deterministic offline fallback (offline_mutator.py) for SQLi, XSS, IDOR, path traversal
- [x] Orchestrator (generate.py): tries LLM, falls back to offline
- [x] Mutation strategies: encoding, whitespace, comments, case variations
- [x] Payload intelligence system (payload_db.py): 1149 annotated payloads across 8 attack categories
- [x] WAF-aware selection: detects WAF from headers, filters to bypass-capable payloads
- [x] DB-aware selection: infers database engine, selects dialect-specific payloads
- [x] Feedback loop (feedback.py): executor results feed back to prioritize successful patterns

### 5. Executor (`src/executor/`) -- COMPLETE

- [x] Plugin architecture with abstract AttackHandler (base.py)
- [x] SessionManager for cookies and authentication (session.py)
- [x] 9 attack handlers:
  - [x] SQL injection (error-based, auth bypass, UNION)
  - [x] XSS (reflected, stored, partial sanitization bypass)
  - [x] IDOR (ID enumeration, response comparison)
  - [x] Path traversal (encoding, OS-specific variants)
  - [x] Auth bypass (direct access, method tampering, headers, default credentials)
  - [x] Info disclosure (headers, errors, sensitive data, directory listing)
  - [x] Command injection (separator, blind time-based, output-based)
  - [x] CSRF (token absence/validation, SameSite, referer)
  - [x] Open redirect (Location header, JavaScript redirect)
- [x] LLM response analysis (response_analyzer.py)
- [x] Rate limiting between requests
- [x] Auth framework integration

### 6. Validator (`src/validator/`) -- COMPLETE

- [x] 4 validation strategies:
  - [x] Differential analysis (compare with/without payload)
  - [x] Multi-payload validation (cross-validate with equivalent payloads)
  - [x] LLM analysis (Claude judgment for ambiguous cases)
  - [x] Timing-based validation (for blind vulnerabilities)
- [x] Confidence scoring with configurable thresholds
- [x] Automatic FP downgrade (confirmed -> potential when below threshold)
- [x] Strategy selection based on vulnerability type

### 7. Reporter (`src/reporter/`) -- COMPLETE

- [x] LLM-generated reports via Claude API
- [x] Template-based fallback (no API key needed)
- [x] PDF export via weasyprint (optional dependency)
- [x] Hybrid RAG chatbot:
  - [x] FAISS vector store with fastembed embeddings
  - [x] NetworkX knowledge graph (8 node types, 6 relationship types)
  - [x] Hybrid retriever with intent detection
  - [x] Three degradation levels (full / partial / TF-IDF fallback)

### 8. Auth Framework (`src/auth/`) -- COMPLETE

- [x] 4 authentication providers:
  - [x] HTTP Basic (basic.py)
  - [x] Cookie/CSRF with token extraction (cookie.py)
  - [x] Bearer/JWT with auto-refresh (bearer.py)
  - [x] OAuth2 authorization code and client credentials (oauth2.py)
- [x] Auto-detection of authentication scheme
- [x] Transparent re-authentication on session expiry
- [x] Shared state with Executor SessionManager

### 9. Proxy (`src/proxy/`) -- COMPLETE

- [x] MITM proxy server via mitmproxy addon (server.py)
- [x] Request/response interception (interceptor.py)
- [x] FlowStore -- SQLite-backed HTTP flow storage (store.py)
- [x] Flow replayer with payload modification (replayer.py)
- [x] Feed adapter -- convert captured flows to scanner input (feed.py)
- [x] CA certificate generation and management (certificate.py)
- [x] Optional dependency (`pip install .[proxy]`)

### 10. Infra & DevOps -- COMPLETE

- [x] Git + branches
- [x] CI GitHub Actions: ruff lint + mypy typecheck + pytest (ci.yml)
- [x] Weekly battle tests against DVWA/WebGoat (battle.yml)
- [x] Dockerfile with healthchecks
- [x] AOP decorators (@logged, @retry, @timed, @safe)
- [x] Pydantic Settings for configuration
- [x] Structured logging (text + JSON), zero print()
- [x] Typed exception hierarchy

### 11. Frontend -- COMPLETE

- [x] React + Vite web interface
- [x] 15+ components (ScannerView, ExpertView, AttackView, ReportView, ChatView, ProxyView, SummaryView, VAEView, Charts, Markdown, ScrollBox, Sidebar)
- [x] SSE streaming for real-time pipeline progress
- [x] Dark theme optimized for security tooling
- [x] Severity distribution charts and attack success rates
- [x] Integrated RAG chat for post-scan analysis

### 12. Testing -- COMPLETE

- [x] 145+ tests across unit, integration, and battle test tiers
- [x] Unit tests: models, expert (42), executor (23), generator (10), infra (44), e2e (4)
- [x] Battle tests: full pipeline against DVWA, WebGoat
- [x] Regression tracker: detection rate snapshots with baseline enforcement

---

## Future improvements

- [ ] Multi-target campaign orchestration
- [ ] Dashboard with historical trend analysis across scans
- [ ] Custom rule authoring UI for the expert system
- [ ] Ollama / local LLM support for air-gapped environments
- [ ] CVSS score integration in reports
- [ ] Conversation history for RAG chatbot sessions

---

## Prerequisites by mode

| Prerequisite | Fixtures mode | Live mode |
|--------------|:------------:|:---------:|
| Python 3.11+ | Required | Required |
| `pip install -e ".[dev]"` | Required | Required |
| `playwright install chromium` | No | Required |
| Docker | No | Required |
| Anthropic API key | No | Recommended |
| nmap | No | Optional (socket fallback) |
| ChromaDB | No | Optional (memory fallback) |
| mitmproxy (`.[proxy]`) | No | Optional |
| weasyprint (`.[pdf]`) | No | Optional |

---

## Estimated cost (Anthropic API)

| Usage | Estimated cost |
|-------|---------------|
| 1 full demo (scan + report + RAG) | ~$0.15 |
| Development phase (20 tests) | ~$3 |
| Realistic total | **< $5** |

> Free credits on Anthropic signup (~$5) are sufficient.
> Free alternative: use Haiku (6x cheaper) or a local model (Ollama).

---

## Main dependencies

| Package | Usage |
|---------|-------|
| `pydantic` + `pydantic-settings` | Data models, validation, configuration |
| `langchain` + `langgraph` | ReAct agent |
| `langchain-anthropic` | Claude LLM (agent, payload generation, reporting, validation) |
| `faiss-cpu` | Vector store for RAG chatbot |
| `fastembed` | Semantic embeddings (BAAI/bge-small-en-v1.5) |
| `networkx` | Knowledge graph for structured RAG queries |
| `requests` + `beautifulsoup4` | HTTP requests + HTML parsing |
| `playwright` | Dynamic SPA analysis (headless Chromium) |
| `python-nmap` | Port scanning (optional) |
| `fastapi` + `sse-starlette` | Backend API with streaming |
| `react` + `vite` | Real-time web interface |
| `weasyprint` | PDF report export (optional) |
| `mitmproxy` | MITM proxy for traffic capture (optional) |
| `ruff` + `mypy` | Linting and type checking (CI) |
| `python-dotenv` | Environment variables |
