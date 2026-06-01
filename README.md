# RedSimulator

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/LangChain-0.2+-1C3C3C?logo=langchain&logoColor=white" alt="LangChain" />
  <img src="https://img.shields.io/badge/Claude-Anthropic-D4A574?logo=anthropic&logoColor=white" alt="Claude" />
  <img src="https://img.shields.io/badge/Playwright-1.40+-2EAD33?logo=playwright&logoColor=white" alt="Playwright" />
  <img src="https://img.shields.io/badge/ChromaDB-0.4+-FF6F00" alt="ChromaDB" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License" />
</p>

AI-powered automated security testing tool that chains 5 AI modules to scan, analyze and exploit vulnerabilities in a target web application (OWASP Juice Shop).

---

## Architecture

```
   ┌──────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐
   │ Scanner  │───>│  Expert  │───>│ Generator │───>│ Executor │───>│ Reporter │
   │  (ReAct) │    │(20 Rules)│    │(LLM+Offline)│  │(9 Handlers)│  │(RAG+LLM) │
   └──────────┘    └──────────┘    └───────────┘    └──────────┘    └──────────┘
                                        │
                                   ┌────┴────┐
                                   │  Infra  │
                                   │(AOP/Logs)│
                                   └─────────┘
```

1. **Scanner** — Autonomous ReAct agent (LangGraph + Claude) for reconnaissance
2. **Expert** — Forward-chaining expert system with 20 OWASP rules + LLM analyst second pass
3. **Generator** — LLM-based payload mutation with deterministic offline fallback
4. **Executor** — 9 attack handlers with plugin architecture and session management
5. **Reporter** — Generates a report + RAG chatbot
6. **Infra** — AOP decorators, Pydantic Settings, structured logging, typed exceptions

The React web interface communicates with the FastAPI backend via **Server-Sent Events** (SSE) to display pipeline progress in real time.

---

## Progress

| Module | Status | Details |
|--------|--------|---------|
| Pydantic Models | ✅ Complete | Data contracts between all modules |
| JSON Fixtures | ✅ Complete | Simulated Juice Shop data for dev/demo |
| Scanner | ✅ Complete | 8 tools, ReAct agent with self-evaluation, dynamic crawling (Playwright), persistent memory |
| Expert System | ✅ Complete | 20 rules in 3 categories + LLM analyst second pass (17/20 fire on Juice Shop fixture) |
| Generator (LLM + Offline) | ✅ Complete | Claude API mutation + deterministic offline fallback (SQLi, XSS, IDOR, path traversal) |
| Executor | ✅ Complete | 9 attack handlers with plugin architecture, session management, LLM response analysis |
| Reporter | ✅ Complete | Template + LLM-generated reports, RAG chatbot with in-memory fallback |
| Orchestrator | ✅ Complete | Full pipeline with fixtures mode |
| FastAPI API | ✅ Complete | SSE streaming, RAG chat endpoint |
| React Frontend | ✅ Complete | 15-file decomposed UI, charts, RAG chat, dark theme |
| Infra | ✅ Complete | AOP decorators, Pydantic Settings, structured logging, typed exceptions |
| Docker | ✅ Complete | Juice Shop + ChromaDB + recon-tools, healthchecks on all services |
| CI | ✅ Complete | GitHub Actions with ruff lint, mypy typecheck, pytest |
| Tests | ✅ Complete | Models, expert, generator, executor covered |

### Remaining improvements

- **RAG**: Production ChromaDB with semantic embeddings, conversation history
- **Reporter**: PDF export, CVSS score integration
- **Tests**: End-to-end pipeline tests, scanner unit coverage expansion

---

## Scanner

```
src/scanner/
├── agent.py            # ReAct agent with self-evaluation and retry loop
├── tools.py            # 8 autonomous tools for the agent
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
# Terminal 1 — Backend
.venv/bin/uvicorn src.api:app --reload --port 8080

# Terminal 2 — Frontend
cd frontend && npm run dev
# Open http://localhost:5173
```

## Tests

```bash
pytest tests/ -v
```

---

## Tech stack

| Package | Usage |
|---------|-------|
| `pydantic` | Data models and validation |
| `langchain` + `langgraph` | ReAct agent |
| `langchain-anthropic` | Claude LLM (agent, payload generation, reporting) |
| `chromadb` | Vector database for RAG |
| `playwright` | Dynamic SPA analysis |
| `fastapi` + `sse-starlette` | Backend API with streaming |
| `react` + `vite` | Real-time web interface |
| `requests` + `beautifulsoup4` | HTTP + HTML parsing |
| `pydantic-settings` | Type-safe configuration from environment |
| `ruff` + `mypy` | Linting and type checking (CI) |

---

## Blog

Read the full technical write-up on the design decisions, AI techniques, and lessons learned: **[Building an AI-Powered Security Testing Pipeline](docs/blog.md)**
