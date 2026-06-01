# RedSimulator — ROADMAP

## Comment lancer le projet

### Prerequis

- Python >= 3.11
- (Optionnel) Docker — pour Juice Shop et ChromaDB
- (Optionnel) Cle API Anthropic — pour les modules LLM
- (Optionnel) nmap — pour le scan de ports avance

### Installation

```bash
cd redsimulator
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Installer Chromium pour Playwright (analyse dynamique des SPA)
python3 -m playwright install chromium
```

### Lancement — mode fixtures (aucune dependance externe)

```bash
# Pipeline complet avec donnees simulees
python3 -m src.orchestrator --fixtures

# Modules individuels
python3 -m src.expert           # Systeme expert seul
python3 -m src.generator        # Generator seul
python3 -m src.executor         # Executor seul
python3 -m src.reporter         # Reporter + RAG seul
python3 -m src.scanner --fixtures  # Scanner avec fixture

# Tests
pytest tests/ -v
```

### Lancement — mode live (avec Juice Shop)

```bash
# 1. Configurer l'environnement
cp .env.example .env
# Editer .env → ANTHROPIC_API_KEY=sk-ant-api03-...

# 2. Lancer les services Docker
docker-compose up -d
# → Juice Shop sur http://localhost:3000
# → ChromaDB sur http://localhost:8000

# 3. Scanner seul (sans cle API = fallback sequentiel)
python3 -m src.scanner

# 4. Pipeline live complet
python3 -m src.orchestrator --target http://localhost:3000
```

---

## Ce qui est fait

### Scanner (`src/scanner/`) — Architecture SRP

| Fichier | Responsabilite | Etat |
|---------|---------------|------|
| `agent.py` | Agent ReAct avec auto-evaluation et boucle de relance | Done |
| `tools.py` | 8 outils : port_scan, endpoint_discovery, header_checker, form_analyzer, probe_endpoint, tech_detector, directory_bruteforce, dns_enum | Done |
| `http_utils.py` | Requetes HTTP securisees + formatage erreurs | Done |
| `crawlers.py` | Decouverte de chemins (HTML + JS bundles + Playwright) | Done |
| `form_parsing.py` | Analyse de formulaires (statique + dynamique Playwright) | Done |
| `tech_detector.py` | Detection des technologies et versions (headers, HTML, JS, package.json, endpoints) | Done |
| `browser.py` | Singleton Playwright (Chromium headless) | Done |
| `memory.py` | Historique de scans persistant par cible | Done |

**Capacites du scanner :**
- 8 outils autonomes pour l'agent + wordlists par categorie
- Auto-evaluation du rapport avec boucle de relance (max 2 iterations)
- Resumes factuels sans heuristiques hardcodees
- Analyse du contenu des reponses (detection de secrets, tokens, code source)
- Extraction de parametres (path params, query params, cles JSON)
- Scan de ports (nmap Docker / nmap local / fallback socket)
- Crawl multi-sources (HTML + JS + Playwright + wordlists)
- Detection de technologies avec versions
- Analyse cookies (Secure, HttpOnly, SameSite) + CORS

### Autres modules

| Module | Fichiers | Etat |
|--------|----------|------|
| Modeles Pydantic | `src/models/*.py` | Done — contrat entre modules |
| Fixtures JSON | `data/fixtures/*.json` | Done — donnees simulees |
| Systeme Expert | `src/expert/engine.py`, `rules.py`, `rules_header.py`, `rules_chaining.py`, `facts.py`, `llm_analyst.py` | Done — 20 regles, 3 categories + analyste LLM |
| Generator (LLM + Offline) | `src/generator/llm_mutator.py`, `offline_mutator.py`, `generate.py` | Done — mutation LLM + fallback offline |
| Executor | `src/executor/base.py`, `session.py`, `attacks/*.py`, `attacks/response_analyzer.py` | Done — 9 handlers, architecture plugin |
| Reporter | `src/reporter/report_generator.py` | Done |
| RAG Chatbot | `src/reporter/rag_chatbot.py` | Done |
| Orchestrateur | `src/orchestrator.py` | Done |
| Infra | `src/infra/` — AOP decorators, Pydantic Settings, structured logging, exceptions | Done |
| Regles OWASP | `rules/owasp_rules.json` | Done |
| Config | `pyproject.toml`, `docker-compose.yml`, `.env.example` | Done |
| CI | GitHub Actions — ruff, mypy, pytest | Done |
| Docker | Dockerfile + docker-compose avec healthchecks | Done |
| Tests | `tests/test_*.py` | Done |

---

## Ce qui reste a faire pour la version finale

### 1. Scanner (`src/scanner/`) — COMPLET

- [x] Implementer header_checker (+ cookies + CORS)
- [x] Implementer form_analyzer (statique + Playwright)
- [x] Decouvrir les endpoints dynamiquement (crawl JS + Playwright)
- [x] Detecter les technologies et versions
- [x] Filtrer les faux formulaires (mat-input-N)
- [x] Structure SRP (7 fichiers specialises)
- [x] Agent ReAct avec Claude (teste et fonctionnel)
- [x] Auto-evaluation du rapport avec boucle de relance
- [x] Resumes factuels sans heuristiques hardcodees
- [x] Analyse du contenu sensible (patterns, pas noms de fichiers)
- [x] Extraction des parametres (path, query, JSON body)
- [x] Wordlists par categorie (common, sensitive, nodejs, backup)
- [x] Nmap Docker pour le fingerprinting de services
- [x] Scan de ports parametrable par l'agent
- [x] probe_endpoint pour investigation approfondie
- [x] Interface React temps reel avec SSE
- [x] API FastAPI avec streaming
- [x] Tests unitaires

### 2. Systeme Expert (`src/expert/`) — COMPLET

- [x] Enrichir avec plus de regles (20 regles au total)
- [x] Regles de vulnerabilites (rules.py — 11 regles) : SQLi, XSS, IDOR, PATH_TRAVERSAL, AUTH_BYPASS, INFO_DISCLOSURE, CSRF, OPEN_REDIRECT, COMMAND_INJECTION, BROKEN_AUTH
- [x] Regles de headers/config (rules_header.py — 4 regles) : MISSING_HSTS, MISSING_XFRAME, INSECURE_COOKIES, SENSITIVE_DATA_EXPOSURE
- [x] Regles de chainage (rules_chaining.py — 5 regles) : CHAIN_BYPASS_EXFIL, CHAIN_XSS_SESSION, CHAIN_IDOR_INFO, XSS_CRITICAL, MULTI_VULN_CRITICAL
- [x] Analyste LLM en deuxieme passe (llm_analyst.py)
- [x] Correlation entre vulnerabilites (chaines d'attaques)
- [x] 17/20 regles s'activent sur la fixture Juice Shop → 14 vecteurs d'attaque

### 3. Generator / LLM + Offline (`src/generator/`) — COMPLET

- [x] Mutation LLM via Claude API (llm_mutator.py)
- [x] Fallback offline deterministe (offline_mutator.py) pour SQLi, XSS, IDOR, path traversal
- [x] Orchestrateur (generate.py) : essaie LLM, tombe en fallback offline
- [x] Strategies de mutation : encodage, whitespace, commentaires, variations de casse

### 4. Executor (`src/executor/`) — COMPLET

- [x] Architecture plugin avec AttackHandler abstrait (base.py)
- [x] SessionManager pour cookies et authentification (session.py)
- [x] 9 handlers d'attaque :
  - [x] SQL injection (error-based, auth bypass, UNION)
  - [x] XSS (reflected, stored, sanitization partielle)
  - [x] IDOR (enumeration d'IDs, comparaison de reponses)
  - [x] Path traversal (encodage, variantes OS)
  - [x] Auth bypass (acces direct, method tampering, headers, credentials par defaut)
  - [x] Info disclosure (headers, erreurs, donnees sensibles, listing de repertoires)
  - [x] Command injection (separateur, blind time-based, output-based)
  - [x] CSRF (absence de token, validation, SameSite, referer)
  - [x] Open redirect (Location header, redirection JS)
- [x] Analyse de reponses par LLM (response_analyzer.py)
- [x] Rate limiting entre les requetes

### 5. Reporter (`src/reporter/`)

- [x] Generation via Claude API
- [ ] Ameliorer le format du rapport (scores CVSS)
- [ ] Ajouter l'export PDF

### 6. RAG Chatbot (`src/reporter/rag_chatbot.py`)

- [x] Fallback en memoire fonctionnel
- [ ] Brancher ChromaDB (Docker) en production
- [ ] Utiliser les embeddings semantiques
- [ ] Ajouter l'historique de conversation

### 7. Infra & DevOps — COMPLET

- [x] Git + branches
- [x] CI GitHub Actions : ruff lint + mypy typecheck + pytest
- [x] Dockerfile avec healthchecks
- [x] AOP decorators (@logged, @retry, @timed, @safe)
- [x] Pydantic Settings pour la configuration
- [x] Structured logging (text + JSON), zero print()
- [x] Hierarchie d'exceptions typees

---

## Prerequis par mode

| Prerequis | Mode fixtures | Mode live |
|-----------|:------------:|:---------:|
| Python 3.11+ | Requis | Requis |
| `pip install -e ".[dev]"` | Requis | Requis |
| `playwright install chromium` | Non | Requis |
| Docker | Non | Requis |
| Cle API Anthropic | Non | Recommande |
| nmap | Non | Optionnel (fallback socket) |
| ChromaDB | Non | Optionnel (fallback memoire) |

---

## Cout estime (API Anthropic)

| Usage | Cout estime |
|-------|-------------|
| 1 demo complete (scan + rapport + RAG) | ~0.15$ |
| Phase developpement (20 tests) | ~3$ |
| Total realiste pour le TP | **< 5$** |

> Les credits gratuits a l'inscription Anthropic (~5$) couvrent largement le TP.
> Alternative gratuite : utiliser Haiku (6x moins cher) ou un modele local (Ollama).

---

## Dependances principales

| Package | Usage |
|---------|-------|
| `pydantic` + `pydantic-settings` | Modeles de donnees, validation, configuration |
| `langchain` + `langgraph` | Agent ReAct |
| `langchain-anthropic` | LLM Claude (agent, generation de payloads, rapport) |
| `requests` | Requetes HTTP |
| `beautifulsoup4` | Parsing HTML statique |
| `playwright` | Analyse dynamique des SPA (Chromium headless) |
| `python-nmap` | Scan de ports (optionnel) |
| `chromadb` | Base vectorielle pour le RAG |
| `fastapi` + `sse-starlette` | Backend API avec streaming |
| `react` + `vite` | Interface web temps reel |
| `ruff` + `mypy` | Linting et verification de types (CI) |
| `python-dotenv` | Variables d'environnement |
