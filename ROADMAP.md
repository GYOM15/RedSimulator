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
python3 -m src.generator        # VAE seul
python3 -m src.executor         # Executor seul
python3 -m src.reporter         # Reporter + RAG seul
python3 -m src.scanner --fixtures  # Scanner avec fixture

# Tests
pytest tests/ -v

# Dashboard
streamlit run src/dashboard.py
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
| `tools.py` | 7 outils : port_scan, endpoint_discovery, header_checker, form_analyzer, probe_endpoint, tech_detector, directory_bruteforce | Done |
| `http_utils.py` | Requetes HTTP securisees + formatage erreurs | Done |
| `crawlers.py` | Decouverte de chemins (HTML + JS bundles + Playwright) | Done |
| `form_parsing.py` | Analyse de formulaires (statique + dynamique Playwright) | Done |
| `tech_detector.py` | Detection des technologies et versions (headers, HTML, JS, package.json, endpoints) | Done |

**Capacites du scanner :**
- 7 outils autonomes pour l'agent + wordlists par categorie
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
| Systeme Expert | `src/expert/engine.py`, `rules.py`, `facts.py` | Done (scaffold) |
| Generator (VAE) | `src/generator/vae_model.py`, `train.py`, `generate.py` | Done (scaffold) |
| Executor | `src/executor/runner.py` | Done (scaffold) |
| Reporter | `src/reporter/report_generator.py` | Done (scaffold) |
| RAG Chatbot | `src/reporter/rag_chatbot.py` | Done (scaffold) |
| Orchestrateur | `src/orchestrator.py` | Done |
| Dashboard | `src/dashboard.py` | Done (scaffold) |
| Regles OWASP | `rules/owasp_rules.json` | Done |
| Config | `pyproject.toml`, `docker-compose.yml`, `.env.example` | Done |
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
- [ ] Tests unitaires

### 2. Systeme Expert (`src/expert/`)

- [ ] Enrichir `owasp_rules.json` avec plus de regles (CSRF, SSRF, XXE, etc.)
- [ ] Affiner les seuils de criticite (score, priorite)
- [ ] Ajouter la correlation entre vulnerabilites (chaines d'attaques)
- [ ] Valider les regles avec les resultats du vrai scan

### 3. Generator / VAE (`src/generator/`)

- [ ] Enrichir `data/payloads/sqli_payloads.txt` avec plus de payloads
- [ ] Ajouter des datasets pour XSS, command injection, path traversal
- [ ] Tuner les hyperparametres du VAE (latent_dim, epochs, lr)
- [ ] Ajouter des metriques de qualite des payloads generes
- [ ] Sauvegarder/charger le modele entraine (`data/vae_model.pt`)

### 4. Executor (`src/executor/`)

- [ ] Ajouter plus de types d'attaques (command injection, path traversal)
- [ ] Gerer les cookies de session et l'authentification
- [ ] Ajouter des checks de succes plus fins (regex, codes HTTP)
- [ ] Ajouter un mode rate-limiting pour ne pas surcharger la cible

### 5. Reporter (`src/reporter/`)

- [ ] Activer la generation via Claude API (remplacer le template statique)
- [ ] Ameliorer le format du rapport (graphiques, scores CVSS)
- [ ] Ajouter l'export PDF

### 6. RAG Chatbot (`src/reporter/rag_chatbot.py`)

- [ ] Brancher ChromaDB (Docker) au lieu du fallback en memoire
- [ ] Utiliser les embeddings d'Anthropic pour le chunking semantique
- [ ] Activer les reponses via Claude API
- [ ] Integrer le chat dans le dashboard Streamlit
- [ ] Ajouter l'historique de conversation

### 7. Dashboard (`src/dashboard.py`)

- [ ] Ajouter le chat RAG interactif dans l'interface
- [ ] Ameliorer les visualisations (graphiques Plotly, heatmap OWASP)
- [ ] Ajouter le lancement du pipeline depuis le dashboard
- [ ] Mode comparaison entre plusieurs scans

### 8. Infra & DevOps

- [ ] Init Git + commit initial + branche `dev`
- [ ] Ajouter CI (GitHub Actions) : lint + tests
- [ ] Dockerfile pour le projet complet
- [ ] Documentation API (docstrings completes)

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
| `pydantic` | Modeles de donnees et validation |
| `langchain` + `langgraph` | Agent ReAct |
| `langchain-anthropic` | LLM Claude |
| `requests` | Requetes HTTP |
| `beautifulsoup4` | Parsing HTML statique |
| `playwright` | Analyse dynamique des SPA (Chromium headless) |
| `python-nmap` | Scan de ports (optionnel) |
| `torch` | VAE (generateur de payloads) |
| `chromadb` | Base vectorielle pour le RAG |
| `streamlit` + `plotly` | Dashboard |
| `python-dotenv` | Variables d'environnement |
