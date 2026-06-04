# RedSimulator

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/LangChain-0.2+-1C3C3C?logo=langchain&logoColor=white" alt="LangChain" />
  <img src="https://img.shields.io/badge/Claude-Anthropic-D4A574?logo=anthropic&logoColor=white" alt="Claude" />
  <img src="https://img.shields.io/badge/Playwright-1.40+-2EAD33?logo=playwright&logoColor=white" alt="Playwright" />
  <img src="https://img.shields.io/badge/FAISS-Meta-0467DF" alt="FAISS" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License" />
</p>

AI-powered automated security testing tool that chains a 6-stage AI pipeline to scan, analyze, exploit, and validate vulnerabilities in web applications.

---

## Architecture

```
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌───────────┐   ┌──────────┐
│ Scanner  │──>│ Passive  │──>│  Expert  │──>│ Generator │──>│ Executor │──>│ Validator │──>│ Reporter │
│  (ReAct) │   │(6 Checks)│   │(20 Rules)│   │(LLM+Intel)│   │(9 Handlers)│  │(4 Strats) │   │(RAG+PDF) │
└──────────┘   └──────────┘   └──────────┘   └───────────┘   └──────────┘   └───────────┘   └──────────┘
                                                   │
                                      ┌────────────┼────────────┐
                                      │            │            │
                                 ┌────┴────┐  ┌────┴────┐  ┌───┴───┐
                                 │  Infra  │  │  Auth   │  │ Proxy │
                                 │(AOP/Logs)│  │(4 Provs)│  │(MITM) │
                                 └─────────┘  └─────────┘  └───────┘
```

1. **Scanner** -- Autonomous ReAct agent (LangGraph + Claude) with 9 tools including API spec discovery, Playwright dynamic analysis, and persistent memory
2. **Passive Scanning** -- 6 non-intrusive checks (headers, cookies, CORS, information disclosure, transport security, sensitive URLs) with CWE references
3. **Expert System** -- Forward-chaining engine with 20 OWASP rules + LLM analyst second pass; passive findings injected as facts
4. **Generator** -- LLM-based payload mutation with offline fallback + payload intelligence system (1149 annotated payloads, WAF-aware selection, feedback loop)
5. **Executor** -- 9 attack handlers with plugin architecture, SessionManager with auth integration
6. **Validator** -- 4 validation strategies (differential, multi-payload, LLM analysis, timing-based), confidence scoring, automatic FP downgrade
7. **Reporter** -- LLM/template report generation + PDF export + FAISS RAG chatbot with NetworkX knowledge graph

The React web interface communicates with the FastAPI backend via **Server-Sent Events** (SSE) to display pipeline progress in real time.

---

## Progress

| Module | Status | Details |
|--------|--------|---------|
| Pydantic Models | ✅ Complete | Data contracts between all modules |
| JSON Fixtures | ✅ Complete | Simulated data for dev/demo |
| Scanner | ✅ Complete | 9 tools (incl. api_spec_scanner), ReAct agent with self-evaluation, Playwright, persistent memory |
| Passive Scanning | ✅ Complete | 6 checks (headers, cookies, CORS, information, transport, sensitive URLs) with CWE refs |
| Expert System | ✅ Complete | 20 rules in 3 categories + LLM analyst second pass |
| Generator | ✅ Complete | LLM mutation + offline fallback + payload intelligence (1149 annotated payloads, WAF/DB-aware) |
| Executor | ✅ Complete | 9 attack handlers, plugin architecture, session management, LLM response analysis |
| Validator | ✅ Complete | 4 strategies (differential, multi-payload, LLM, timing), confidence scoring, FP auto-downgrade |
| Reporter | ✅ Complete | Template + LLM reports, PDF export (weasyprint), hybrid RAG chatbot (FAISS + knowledge graph) |
| Auth | ✅ Complete | 4 providers (basic, cookie/CSRF, bearer/JWT, OAuth2), auto re-auth |
| Proxy | ✅ Complete | MITM proxy (mitmproxy), FlowStore (SQLite), replayer, feed adapter, CA cert manager |
| Orchestrator | ✅ Complete | Full pipeline with fixtures and live modes |
| FastAPI API | ✅ Complete | SSE streaming, RAG chat endpoint |
| React Frontend | ✅ Complete | 15+ components (incl. ProxyView), charts, RAG chat, dark theme |
| Infra | ✅ Complete | AOP decorators, Pydantic Settings, structured logging, typed exceptions |
| Docker | ✅ Complete | Juice Shop + ChromaDB + recon-tools, healthchecks on all services |
| CI | ✅ Complete | GitHub Actions: lint + typecheck + test (ci.yml), weekly battle tests (battle.yml) |
| Tests | ✅ Complete | 145+ tests, battle testing (DVWA, WebGoat), regression tracker |

### Future improvements

- Multi-target campaign orchestration
- Dashboard with historical trend analysis
- Custom rule authoring UI
- Ollama / local LLM support for air-gapped environments

---

## Scanner

```
src/scanner/
├── agent.py            # ReAct agent with self-evaluation and retry loop
├── tools.py            # 9 autonomous tools for the agent
├── api_specs/          # OpenAPI/Swagger/GraphQL spec discovery and parsing
├── http_utils.py       # HTTP requests + thread-safe cache
├── crawlers.py         # Path discovery (HTML + JS + Playwright)
├── form_parsing.py     # Form analysis (static + dynamic)
├── tech_detector.py    # Technology and version detection
├── browser.py          # Playwright singleton (headless Chromium)
└── memory.py           # Persistent scan history per target
```

| Tool | Description |
|------|-------------|
| `port_scan` | Port scanning (nmap Docker / local / socket fallback) |
| `endpoint_discovery` | HTML + JS + Playwright crawling + content analysis |
| `header_checker` | Security headers + cookies + CORS |
| `form_analyzer` | Static and dynamic forms (Playwright) |
| `directory_bruteforce` | Category-based wordlists (common, sensitive, nodejs, backup) |
| `tech_detector` | Technologies and versions (headers, JS, package.json) |
| `probe_endpoint` | Custom HTTP testing (method, body) |
| `dns_enum` | Subdomain enumeration (subfinder, crt.sh, bruteforce) |
| `api_spec_scanner` | OpenAPI/Swagger/GraphQL spec discovery and endpoint extraction |

---

## Passive Scanning

```
src/passive/
├── analyzer.py         # Passive scan orchestrator
├── models.py           # PassiveFinding with CWE references
└── checks/
    ├── headers.py      # Missing security headers (HSTS, X-Frame, CSP, etc.)
    ├── cookies.py      # Cookie attribute analysis (Secure, HttpOnly, SameSite)
    ├── cors.py         # CORS misconfiguration detection
    ├── information.py  # Information disclosure (server banners, error pages)
    ├── transport.py    # Transport security (HTTPS enforcement, mixed content)
    └── sensitive_urls.py  # Sensitive URL patterns in query strings
```

All findings include CWE identifiers for standards compliance. Passive findings are injected as facts into the expert system for rule evaluation.

---

## Auth Framework

```
src/auth/
├── manager.py          # Auto-detection and re-auth orchestration
├── models.py           # Credential and session models
└── providers/
    ├── basic.py        # HTTP Basic authentication
    ├── cookie.py       # Cookie-based auth with CSRF token extraction
    ├── bearer.py       # Bearer token / JWT authentication
    └── oauth2.py       # OAuth2 authorization code and client credentials flows
```

The auth manager auto-detects the authentication scheme from the target's responses and transparently re-authenticates when sessions expire. All auth state is shared with the Executor's SessionManager.

---

## Proxy

```
src/proxy/
├── server.py           # MITM proxy server (mitmproxy addon)
├── interceptor.py      # Request/response interception and modification
├── store.py            # FlowStore — SQLite-backed HTTP flow storage
├── replayer.py         # Replay captured flows with modifications
├── feed.py             # Feed adapter — import proxy flows into the pipeline
├── certificate.py      # CA certificate generation and management
└── models.py           # Flow and intercept rule models
```

The MITM proxy captures live traffic for analysis, stores flows in SQLite, and can replay them with payload modifications. The feed adapter converts captured flows into scanner-compatible input, enabling proxy-driven scanning workflows.

---

## Payload Intelligence

The generator includes a payload intelligence system (`src/generator/payload_db.py`) that goes beyond simple mutation:

- **Annotated payloads**: 1149 payloads across 8 attack categories stored as `.jsonl` files with metadata (target databases, injection contexts, WAF bypass capabilities)
- **WAF-aware selection**: Automatic WAF detection from response headers, with payload filtering to select variants known to bypass the detected WAF
- **DB-aware selection**: Database engine inference from error messages and headers, selecting payloads targeting the specific SQL dialect
- **Feedback loop** (`src/generator/feedback.py`): Executor results feed back into the generator to prioritize successful payload families and deprioritize blocked patterns

---

## Validator

```
src/validator/
├── validator.py        # Validation orchestrator with strategy selection
├── confidence.py       # Confidence scoring and threshold management
├── models.py           # ValidationResult with confidence levels
└── strategies/
    ├── differential.py   # Compare responses with/without payload
    ├── multi_payload.py  # Cross-validate with semantically equivalent payloads
    ├── llm_analysis.py   # LLM-based response analysis for ambiguous cases
    └── timing.py         # Timing-based validation for blind vulnerabilities
```

The validator runs after the executor to filter false positives. Each finding receives a confidence score; findings below threshold are automatically downgraded. The multi-strategy approach catches FPs that any single method would miss.

---

## Prerequisites

| Prerequisite | Fixtures mode | Live mode |
|--------------|:------------:|:---------:|
| Python 3.11+ | Required | Required |
| Node.js 18+ | Required (frontend) | Required |
| Docker | No | Required |
| Anthropic API key | No | Recommended |
| Playwright (Chromium) | No | Required |

## Installation

```bash
git clone <repo-url>
cd redsimulator

# Python backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python3 -m playwright install chromium

# Optional dependencies
pip install -e ".[proxy]"   # MITM proxy support (mitmproxy)
pip install -e ".[pdf]"     # PDF report export (weasyprint)

# React frontend
cd frontend && npm install && cd ..

# Configuration
cp .env.example .env
# Edit .env with your Anthropic API key (optional)

# Docker (Juice Shop + ChromaDB + recon-tools)
docker-compose up -d
```

## Usage

### Fixtures mode (no Docker, no API key)

```bash
python3 -m src.orchestrator --fixtures
python3 -m src.scanner --fixtures
python3 -m src.expert
python3 -m src.generator
python3 -m src.executor --fixtures
python3 -m src.reporter
```

### Live mode (with Juice Shop)

```bash
docker-compose up -d
python3 -m src.scanner
python3 -m src.orchestrator --target http://localhost:3000
```

### Web interface

```bash
# Terminal 1 -- Backend
.venv/bin/uvicorn src.api:app --reload --port 8080

# Terminal 2 -- Frontend
cd frontend && npm run dev
# Open http://localhost:5173
```

## Tests

```bash
# Unit and integration tests
pytest tests/ -v

# Battle tests (requires Docker targets)
pytest tests/battle/ -v
```

---

## Tech stack

| Package | Usage |
|---------|-------|
| `pydantic` + `pydantic-settings` | Data models, validation, type-safe configuration |
| `langchain` + `langgraph` | ReAct agent |
| `langchain-anthropic` | Claude LLM (agent, payload generation, reporting, validation) |
| `faiss-cpu` | Vector store for RAG chatbot |
| `fastembed` | Semantic embeddings (BAAI/bge-small-en-v1.5) |
| `networkx` | Knowledge graph for structured RAG queries |
| `playwright` | Dynamic SPA analysis |
| `fastapi` + `sse-starlette` | Backend API with streaming |
| `react` + `vite` | Real-time web interface |
| `requests` + `beautifulsoup4` | HTTP + HTML parsing |
| `weasyprint` | PDF report export (optional) |
| `mitmproxy` | MITM proxy for traffic capture (optional) |
| `ruff` + `mypy` | Linting and type checking (CI) |

---

## Blog

Read the full technical write-up on the design decisions, AI techniques, and lessons learned: **[Building an AI-Powered Security Testing Pipeline](docs/blog.md)**
