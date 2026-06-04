"""Agent ReAct de reconnaissance.

Cet agent utilise LangGraph + Claude pour orchestrer les outils de scan
et produire un ScanResult structure. Il raisonne etape par etape (ReAct)
pour decider quels outils utiliser et comment interpreter les resultats.
"""

import json
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
from langchain_core.tools import tool

from src.infra.config import settings
from src.infra.decorators import logged, retry
from src.infra.exceptions import LLMError, ScanTimeoutError
from src.infra.logging import get_logger
from src.models import ScanResult

from .http_utils import clear_cache
from .memory import get_previous_context, save_scan
from .tech_detector import detect_technologies
from .tools import (
    api_spec_scanner,
    directory_bruteforce,
    dns_enum,
    endpoint_discovery,
    form_analyzer,
    header_checker,
    port_scan,
    probe_endpoint,
    tech_detector,
)

logger = get_logger(__name__)

ENV_PATH = Path(__file__).parent.parent.parent / ".env"
load_dotenv(ENV_PATH, override=True)

SYSTEM_PROMPT = """Tu es un pentester autonome specialise en reconnaissance web.

STRATEGIE EN 2 PHASES :

PHASE 1 — Appelle ces outils dans un seul message (ils s'executent en parallele) :
- port_scan(target)
- endpoint_discovery(target)
- header_checker(target)
- tech_detector(target)
- directory_bruteforce(target, category="sensitive")
- api_spec_scanner(target) — Decouvre les specs OpenAPI/Swagger/GraphQL
- dns_enum(target) — SEULEMENT si la cible est un domaine reel (pas localhost/IP)

PHASE 2 — Base tes decisions sur les RESULTATS de la Phase 1 :
- form_analyzer : utilise UNIQUEMENT les endpoints decouverts par endpoint_discovery.
  Choisis les endpoints qui semblent interactifs (pages HTML avec status 200, pas les API JSON).
  N'INVENTE JAMAIS un chemin. Utilise ceux que tu as decouverts.
- probe_endpoint : teste les endpoints avec status 401 ou qui semblent sensibles.
  Essaie d'autres methodes (POST, PUT, DELETE) ou un body JSON.
- directory_bruteforce : adapte la categorie aux technologies detectees.
  Node.js → "nodejs". Backups → "backup".
  Pour un scan approfondi → "seclists/web-common" (4700 chemins SecLists).
- port_scan : si tech_detector detecte MongoDB → ports="27017". Redis → ports="6379".
Puis soumets le rapport avec submit_scan_report.

OUTILS :
- port_scan(target, ports="") — Sans ports = ports courants. Avec ports = scan cible.
- endpoint_discovery(target) — Crawle HTML + JS + rendu dynamique. Retourne endpoints + fichiers sensibles.
- header_checker(target, extra_headers="") — Headers de securite, cookies, CORS.
- form_analyzer(target, endpoint) — Analyse les formulaires d'un endpoint SPECIFIQUE.
- tech_detector(target) — Technologies et versions.
- directory_bruteforce(target, category) — Custom: "common", "sensitive", "nodejs", "backup".
  SecLists: "seclists/web-common" (4700), "seclists/web-directories" (30000), "seclists/api-endpoints" (285).
- api_spec_scanner(target) — Decouvre les specs OpenAPI/Swagger/GraphQL.
  Sonde /swagger.json, /openapi.json, /graphql, etc. et parse les endpoints, parametres et auth.
  Utile pour completer endpoint_discovery avec les endpoints documentes.
- dns_enum(target) — Enumere les sous-domaines (subfinder + crt.sh + bruteforce DNS).
  NE PAS appeler sur localhost ou une IP.
- probe_endpoint(target, path, method, body) — Teste un endpoint avec methode/body custom.

PERFORMANCE : Appelle le MAXIMUM d'outils par message. Ne fais PAS un outil par message.

CORRELATION — Apres la Phase 2, avant de soumettre, identifie les chaines d'attaque :
- Login + pas de CSP + pas de rate limiting = risque bruteforce + XSS
- API retourne 201 sans auth = inscription ouverte
- Fichier .env expose + cles dans le contenu = compromission immediate
- Admin sans auth + CORS ouvert = prise de controle possible
Inclus ces observations dans ton rapport.

{memory_context}

SCHEMA JSON pour submit_scan_report :
{{
  "target": "URL",
  "scan_timestamp": "ISO 8601 avec timezone -04:00",
  "open_ports": [{{"port": 3000, "service": "http", "version": "Express 4.17"}}],
  "endpoints": [{{"path": "/api/Users", "method": "GET", "status_code": 401, "auth_required": true, "parameters": []}}],
  "technologies": ["Angular 16", "Express 4.17", "SQLite"],
  "headers": {{"missing_security_headers": ["CSP"], "server_info_leaked": false}},
  "forms": [{{"endpoint": "/#/login", "fields": [{{"name": "email", "type": "text", "placeholder": ""}}], "method": "POST", "action": "", "source": "dynamic"}}]
}}

REGLES ABSOLUES :
- N'invente AUCUNE donnee. Utilise UNIQUEMENT les resultats de tes outils.
- Pour form_analyzer, utilise UNIQUEMENT des endpoints retournes par endpoint_discovery.
- Inclus TOUS les endpoints decouverts dans le rapport, pas seulement les interessants.
"""


# ---------- Conteneur pour capturer le resultat de l'agent ----------


class _ScanResultHolder:
    """Conteneur mutable pour capturer le ScanResult depuis le tool submit."""

    def __init__(self):
        self.result: ScanResult | None = None


def _build_submit_tool(holder: _ScanResultHolder):
    """Cree l'outil de soumission qui stocke le resultat dans le holder."""

    @tool
    def submit_scan_report(report_json: str) -> str:
        """Soumet le rapport de scan final. Le JSON doit correspondre au schema ScanResult.

        Args:
            report_json: JSON du rapport au format ScanResult.

        Returns:
            Confirmation ou erreur de validation.
        """
        try:
            data = json.loads(report_json)
            scan_result = ScanResult.model_validate(data)
            holder.result = scan_result
            logger.info("Rapport de scan valide avec succes!")
            logger.debug("  - Cible: %s", scan_result.target)
            logger.debug("  - Ports ouverts: %d", len(scan_result.open_ports))
            logger.debug("  - Endpoints: %d", len(scan_result.endpoints))
            logger.debug("  - Technologies: %s", scan_result.technologies)
            logger.debug("  - Formulaires: %d", len(scan_result.forms))
            return f"Rapport valide. {len(scan_result.endpoints)} endpoints, {len(scan_result.forms)} formulaires."
        except Exception as e:
            return f"Erreur de validation: {e}. Corrige le JSON et reessaie."

    return submit_scan_report


def _safe_invoke(tool_func, params: dict, fallback=None):
    """Invoque un tool LangChain et parse le JSON retourne."""
    if fallback is None:
        fallback = []
    try:
        result_json = tool_func.invoke(params)
        return json.loads(result_json)
    except Exception as e:
        logger.warning("%s echoue: %s", tool_func.name, e)
        return fallback


class ReconAgent:
    """Agent ReAct de reconnaissance de securite."""

    def __init__(self, target_url: str, on_event: Callable[[str, dict], None] | None = None):
        self.target_url = target_url
        self._holder = _ScanResultHolder()
        self._on_event = on_event or (lambda t, d: None)
        self.tools = [
            port_scan,
            endpoint_discovery,
            header_checker,
            form_analyzer,
            probe_endpoint,
            tech_detector,
            directory_bruteforce,
            api_spec_scanner,
            dns_enum,
            _build_submit_tool(self._holder),
        ]
        self.scan_result: ScanResult | None = None
        self.agent_messages: list = []

    def _emit(self, event_type: str, data: dict):
        """Envoie un evenement au frontend en temps reel."""
        self._on_event(event_type, data)

    def _emit_incremental_stats(self, tool_name: str, raw_content: str):
        """Parse le resultat d'un outil et emet les compteurs mis a jour."""
        try:
            data = json.loads(raw_content)
        except (json.JSONDecodeError, TypeError):
            return

        if tool_name == "port_scan" and isinstance(data, list):
            for port in data:
                self._emit("port", port)
                time.sleep(0.1)
        elif tool_name == "endpoint_discovery" and isinstance(data, list):
            for ep in data:
                self._emit("endpoint", ep)
            self._emit(
                "scan_result",
                {"endpoints": len(data), "ports": 0, "forms": 0, "missing_headers": []},
            )
        elif tool_name == "header_checker" and isinstance(data, dict):
            for h in data.get("missing_security_headers", []):
                self._emit("missing_header", {"name": h})
                time.sleep(0.05)
        elif tool_name == "tech_detector" and isinstance(data, list):
            for tech in data:
                if isinstance(tech, str):
                    self._emit("technology", {"name": tech})
                    time.sleep(0.1)
        elif tool_name == "form_analyzer" and isinstance(data, list):
            for form in data:
                self._emit("form", form)
                time.sleep(0.1)

    @logged
    def run(self) -> ScanResult:
        """Lance l'agent de reconnaissance.

        Strategie hybride :
        1. Tente l'agent ReAct (autonome, intelligent)
        2. Si reussi, complete les lacunes avec le fallback
        3. Si echec, fallback complet

        Cette approche combine l'intelligence de l'agent
        avec la fiabilite du fallback.
        """
        import signal

        SCAN_TIMEOUT = 90  # secondes

        def _timeout_handler(signum, frame):
            raise ScanTimeoutError("Timeout global du scan")

        clear_cache()  # Vider le cache entre les scans
        self._emit(
            "scan_log",
            {"text": f"Demarrage de la reconnaissance sur {self.target_url} (max {SCAN_TIMEOUT}s)"},
        )

        # Installer le timeout (Unix seulement)
        old_handler = None
        try:
            old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(SCAN_TIMEOUT)
        except (AttributeError, ValueError):
            pass  # Windows ou thread non-principal

        try:
            scan = None
            try:
                result = self._run_react_agent()
                if result:
                    self._emit(
                        "scan_log", {"text": "Agent termine — enrichissement des resultats..."}
                    )
                    scan = self._enrich_agent_result(result)
            except ScanTimeoutError:
                self._emit(
                    "scan_log", {"text": f"Timeout {SCAN_TIMEOUT}s atteint — passage au fallback"}
                )
            except Exception as e:
                self._emit("scan_log", {"text": f"Agent LLM indisponible: {e}"})

            if scan is None:
                self._emit("scan_log", {"text": "Fallback: execution sequentielle des outils..."})
                scan = self._fallback_sequential()

            # Calculer le score de risque
            risk = scan.compute_risk_score()
            self._emit(
                "scan_log",
                {
                    "text": f"Score de risque: {risk['score']}/100 ({risk['level']}) — {len(risk['findings'])} constat(s)"
                },
            )

            # Sauvegarder dans la memoire
            changes = save_scan(scan)
            if changes.get("first_scan"):
                self._emit(
                    "scan_log", {"text": "Premier scan sur cette cible — historique initialise."}
                )
            elif changes.get("changes"):
                for c in changes["changes"]:
                    self._emit(
                        "scan_log",
                        {
                            "text": f"Changement detecte: {c['type']} — {c.get('details', c.get('count', ''))}"
                        },
                    )

            return scan
        finally:
            # Annuler le timeout
            try:
                signal.alarm(0)
                if old_handler is not None:
                    signal.signal(signal.SIGALRM, old_handler)
            except (AttributeError, ValueError):
                pass
            from .browser import shutdown

            shutdown()

    def _create_llm(self):
        """Create the LLM instance based on the configured provider."""
        provider = getattr(settings, "llm_provider", "anthropic").lower().strip()

        if provider == "ollama":
            try:
                from langchain_ollama import ChatOllama

                ollama_model = getattr(settings, "ollama_model", "llama3.1")
                ollama_url = getattr(settings, "ollama_url", "http://localhost:11434")
                logger.info("Using Ollama LLM: %s at %s", ollama_model, ollama_url)
                return ChatOllama(
                    model=ollama_model,
                    base_url=ollama_url,
                    temperature=settings.llm_temperature,
                )
            except ImportError:
                logger.warning("langchain-ollama not installed, falling back to Anthropic")
                # Fall through to Anthropic

        # Default: Anthropic
        if not settings.anthropic_api_key:
            logger.warning("No LLM API key configured, agent mode unavailable")
            return None

        from langchain_anthropic import ChatAnthropic

        logger.info("Using Anthropic LLM: %s", settings.llm_model)
        return ChatAnthropic(
            model=settings.llm_model,
            temperature=settings.llm_temperature,
            api_key=settings.anthropic_api_key,
        )

    @retry(max_attempts=2, exceptions=(LLMError,))
    def _run_react_agent(self) -> ScanResult | None:
        """Execute l'agent ReAct avec auto-evaluation.

        Boucle :
        1. L'agent scanne la cible et soumet un rapport
        2. On evalue le rapport (couverture, champs manquants)
        3. Si incomplet, on relance l'agent avec un feedback
        4. Maximum 2 iterations pour controler le cout

        Returns:
            ScanResult valide ou None si l'agent echoue.
        """
        from langgraph.prebuilt import create_react_agent

        llm = self._create_llm()
        if llm is None:
            raise ValueError("No LLM provider available (check API key or Ollama config)")

        agent = create_react_agent(llm, self.tools)

        max_iterations = 1

        # Injecter le contexte memoire des scans precedents
        memory_ctx = get_previous_context(self.target_url)
        prompt = SYSTEM_PROMPT.format(
            memory_context=memory_ctx
            if memory_ctx
            else "Premier scan sur cette cible — aucun historique."
        )

        messages = [
            {"role": "system", "content": prompt},
            {
                "role": "user",
                "content": f"Scanne la cible {self.target_url} et soumets un rapport complet.",
            },
        ]

        for iteration in range(max_iterations):
            self._emit(
                "scan_log",
                {"text": f"Iteration {iteration + 1}/{max_iterations} — l'agent raisonne..."},
            )

            # Streamer les etapes de l'agent en temps reel
            steps = []
            for event in agent.stream({"messages": messages}, stream_mode="updates"):
                for _node_name, node_data in event.items():
                    for msg in node_data.get("messages", []):
                        msg_type = type(msg).__name__
                        if msg_type == "AIMessage":
                            raw_content = getattr(msg, "content", "")
                            tool_calls = getattr(msg, "tool_calls", [])
                            # Extraire le texte si content est une liste d'objets
                            if isinstance(raw_content, list):
                                text_parts = [
                                    block.get("text", "")
                                    for block in raw_content
                                    if isinstance(block, dict) and block.get("type") == "text"
                                ]
                                content = " ".join(text_parts).strip()
                            else:
                                content = str(raw_content).strip()
                            if content:
                                step = {"type": "think", "content": content}
                                steps.append(step)
                                self._emit("agent_step", step)
                                time.sleep(0.3)
                            for tc in tool_calls:
                                step = {
                                    "type": "act",
                                    "tool": tc.get("name", ""),
                                    "args": tc.get("args", {}),
                                }
                                steps.append(step)
                                self._emit("agent_step", step)
                                time.sleep(0.2)
                        elif msg_type == "ToolMessage":
                            content = getattr(msg, "content", "")
                            name = getattr(msg, "name", "")
                            preview = content[:500] + "..." if len(content) > 500 else content
                            step = {"type": "observe", "tool": name, "content": preview}
                            steps.append(step)
                            self._emit("agent_step", step)
                            time.sleep(0.2)
                            # Mettre a jour les compteurs en temps reel
                            self._emit_incremental_stats(name, content)

            self.agent_messages.extend(steps)

            # Verifier si l'agent a soumis un rapport valide
            if self._holder.result:
                feedback = self._evaluate_scan_result(self._holder.result)

                if feedback is None:
                    self._emit("scan_log", {"text": "Rapport complet — auto-evaluation reussie"})
                    self.scan_result = self._holder.result
                    return self.scan_result

                if iteration < max_iterations - 1:
                    self._emit(
                        "scan_log", {"text": f"Rapport incomplet — relance: {feedback[:100]}"}
                    )
                    self._holder.result = None
                    messages = [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": f"Scanne la cible {self.target_url}. Ton rapport precedent etait incomplet. {feedback} Corrige et resoumets.",
                        },
                    ]
                    self.agent_messages.append(
                        {"type": "think", "content": f"Auto-evaluation: {feedback}"}
                    )
                    continue
                else:
                    self._emit("scan_log", {"text": "Derniere iteration — rapport accepte"})
                    self.scan_result = self._holder.result
                    return self.scan_result

        self._emit("scan_log", {"text": "L'agent n'a pas soumis de rapport"})
        return None

    def _evaluate_scan_result(self, result: ScanResult) -> str | None:
        """Evalue si le ScanResult est complet.

        Verifie objectivement les champs sans heuristiques sur les noms.
        Retourne un feedback si incomplet, None si OK.
        """
        issues = []

        if not result.open_ports:
            issues.append("Aucun port trouve. Utilise port_scan.")

        if not result.endpoints:
            issues.append("Aucun endpoint trouve. Utilise endpoint_discovery.")

        if not result.technologies:
            issues.append("Aucune technologie detectee. Utilise tech_detector.")

        if not result.headers.missing_security_headers and not result.headers.server_info_leaked:
            issues.append("Headers non analyses. Utilise header_checker.")

        if not result.forms:
            # Verifier s'il y a des endpoints qui pourraient avoir des formulaires
            has_pages = any(
                ep.status_code == 200
                and not ep.path.startswith("/api/")
                and not ep.path.startswith("/rest/")
                for ep in result.endpoints
            )
            if has_pages:
                issues.append(
                    "Aucun formulaire trouve mais des pages existent. Utilise form_analyzer sur les pages qui semblent interactives."
                )

        if not issues:
            return None

        return " ".join(issues)

    def _enrich_agent_result(self, result: ScanResult) -> ScanResult:
        """Complete les lacunes du scan de l'agent.

        L'agent est intelligent mais parfois incomplet.
        Cette methode verifie et complete :
        - Technologies manquantes (si l'agent n'a pas appele tech_detector)
        - Headers manquants (si l'agent a oublie)
        - Ports manquants (si le scan etait partiel)
        """
        enriched = False

        # 1. Technologies — si l'agent en a trouve peu ou aucune
        if len(result.technologies) < 3:
            logger.info("Completion des technologies...")
            techs = self._detect_technologies()
            if len(techs) > len(result.technologies):
                result.technologies = techs
                enriched = True

        # 2. Headers — si vides
        if not result.headers.missing_security_headers:
            logger.info("Completion des headers...")
            headers = self._check_headers()
            if headers.get("missing_security_headers"):
                result.headers.missing_security_headers = headers["missing_security_headers"]
                result.headers.server_info_leaked = headers.get("server_info_leaked", False)
                enriched = True

        # 3. Ports — si l'agent n'en a trouve aucun
        if not result.open_ports:
            logger.info("Completion des ports...")
            ports = self._scan_ports()
            if ports:
                from src.models import PortInfo

                result.open_ports = [PortInfo(**p) if isinstance(p, dict) else p for p in ports]
                enriched = True

        if enriched:
            logger.info("Scan enrichi avec les donnees manquantes")
        else:
            logger.info("Scan complet, rien a ajouter")

        self.scan_result = result
        return result

    def _extract_reasoning(self, result: dict) -> list:
        """Extrait le raisonnement de l'agent depuis les messages."""
        reasoning = []
        for msg in result.get("messages", []):
            msg_type = type(msg).__name__
            if msg_type == "AIMessage":
                raw_content = getattr(msg, "content", "")
                tool_calls = getattr(msg, "tool_calls", [])
                if isinstance(raw_content, list):
                    content = " ".join(
                        b.get("text", "")
                        for b in raw_content
                        if isinstance(b, dict) and b.get("type") == "text"
                    ).strip()
                else:
                    content = str(raw_content).strip()
                if content:
                    reasoning.append({"type": "think", "content": content})
                for tc in tool_calls:
                    reasoning.append(
                        {
                            "type": "act",
                            "tool": tc.get("name", ""),
                            "args": tc.get("args", {}),
                        }
                    )
            elif msg_type == "ToolMessage":
                content = getattr(msg, "content", "")
                name = getattr(msg, "name", "")
                # Tronquer les longues reponses pour le dashboard
                preview = content[:500] + "..." if len(content) > 500 else content
                reasoning.append(
                    {
                        "type": "observe",
                        "tool": name,
                        "content": preview,
                    }
                )
        return reasoning

    def _fallback_sequential(self) -> ScanResult:
        """Fallback : orchestre les outils sequentiellement sans LLM."""
        self._emit("scan_log", {"text": "Scan des ports..."})
        ports = self._scan_ports()
        for p in ports:
            self._emit("port", p)
            time.sleep(0.1)
        self._emit("scan_log", {"text": f"{len(ports)} ports trouves"})

        self._emit("scan_log", {"text": "Decouverte des endpoints..."})
        endpoints = self._discover_endpoints()
        for ep in endpoints:
            self._emit("endpoint", ep)
        self._emit("scan_log", {"text": f"{len(endpoints)} endpoints decouverts"})

        self._emit("scan_log", {"text": "Verification des headers..."})
        headers = self._check_headers()
        for h in headers.get("missing_security_headers", []):
            self._emit("missing_header", {"name": h})
            time.sleep(0.05)
        self._emit(
            "scan_log",
            {"text": f"{len(headers.get('missing_security_headers', []))} headers manquants"},
        )

        self._emit("scan_log", {"text": "Detection des technologies..."})
        technologies = self._detect_technologies()
        for tech in technologies:
            self._emit("technology", {"name": tech})
            time.sleep(0.1)
        self._emit(
            "scan_log",
            {"text": f"Technologies: {', '.join(technologies[:5]) if technologies else 'aucune'}"},
        )

        self._emit("scan_log", {"text": "Analyse des formulaires..."})
        forms = self._analyze_forms(endpoints)
        for form in forms:
            self._emit("form", form)
            time.sleep(0.1)
        self._emit("scan_log", {"text": f"{len(forms)} formulaires trouves"})

        self.scan_result = ScanResult(
            target=self.target_url,
            scan_timestamp=datetime.now(ZoneInfo("America/Toronto")).isoformat(),
            open_ports=ports,
            endpoints=endpoints,
            technologies=technologies,
            headers=headers,
            forms=forms,
        )
        return self.scan_result

    def _scan_ports(self) -> list:
        """Scanne les ports ouverts sur la cible."""
        result = _safe_invoke(port_scan, {"target": self.target_url}, fallback={})
        if isinstance(result, dict):
            return result.get("ports", [])
        return result

    def _discover_endpoints(self) -> list:
        """Decouvre les endpoints accessibles."""
        result = _safe_invoke(endpoint_discovery, {"target": self.target_url}, fallback={})
        if isinstance(result, dict):
            return result.get("endpoints", [])
        return result

    def _check_headers(self) -> dict:
        """Verifie les headers de securite."""
        return _safe_invoke(
            header_checker,
            {"target": self.target_url},
            fallback={"missing_security_headers": [], "server_info_leaked": False},
        )

    def _detect_technologies(self) -> list:
        """Detecte les technologies utilisees par la cible."""
        try:
            return detect_technologies(self.target_url)
        except Exception as e:
            logger.warning("Detection technologies echouee: %s", e)
            return []

    def _analyze_forms(self, endpoints: list) -> list:
        """Analyse les formulaires sur les endpoints pertinents.

        Selectionne intelligemment quels endpoints analyser :
        - Endpoints avec des noms suggerant un formulaire (login, register, contact, etc.)
        - Routes Angular (hash routes #/)
        - Ignore les API JSON, fichiers statiques, etc.
        """
        forms = []
        analyzed = set()

        # Patterns d'endpoints susceptibles d'avoir des formulaires
        form_patterns = (
            "login",
            "register",
            "contact",
            "forgot",
            "reset",
            "signup",
            "signin",
            "complain",
            "feedback",
            "search",
            "payment",
            "checkout",
            "basket",
            "chatbot",
            "admin",
        )

        for ep in endpoints:
            path = ep.get("path", "")
            status = ep.get("status_code", 0)

            # Ignorer les API JSON, fichiers statiques, et erreurs
            if status != 200:
                continue
            if path.startswith("/api/") or path.startswith("/rest/"):
                continue
            if path.endswith((".json", ".xml", ".txt", ".js", ".css")):
                continue

            # Analyser les routes Angular et les pages avec des noms pertinents
            is_angular = "#/" in path
            is_form_like = any(p in path.lower() for p in form_patterns)

            if (is_angular or is_form_like) and path not in analyzed:
                analyzed.add(path)
                result = _safe_invoke(
                    form_analyzer,
                    {"target": self.target_url, "endpoint": path},
                )
                for form in result:
                    if form.get("fields"):
                        form["endpoint"] = path
                        forms.append(form)

        return forms

    @staticmethod
    def from_fixture() -> ScanResult:
        """Charge le ScanResult depuis la fixture JSON."""
        fixture_path = (
            Path(__file__).parent.parent.parent / "data" / "fixtures" / "scan_result.json"
        )
        data = json.loads(fixture_path.read_text())
        result = ScanResult.model_validate(data)
        logger.info("Fixture chargee: %s, %d endpoints", result.target, len(result.endpoints))
        return result


if __name__ == "__main__":
    import sys

    from src.infra.logging import setup_logging

    setup_logging(level=settings.log_level, fmt=settings.log_format)

    if "--fixture" in sys.argv or "--fixtures" in sys.argv:
        logger.info("=== Mode fixture ===")
        scan = ReconAgent.from_fixture()
    else:
        target = settings.target_url
        agent = ReconAgent(target)
        scan = agent.run()

        # Afficher le raisonnement de l'agent
        if agent.agent_messages:
            logger.info("=" * 60)
            logger.info("Raisonnement de l'agent:")
            logger.info("=" * 60)
            for step in agent.agent_messages:
                if step["type"] == "think":
                    logger.info("  THINK: %s", step["content"][:200])
                elif step["type"] == "act":
                    logger.info("  ACT:   %s(%s)", step["tool"], step["args"])
                elif step["type"] == "observe":
                    logger.info("  OBS:   %s -> %s", step["tool"], step["content"][:100])

    logger.info("=" * 60)
    logger.info("Resultat du scan:")
    logger.info("=" * 60)
    logger.info(scan.model_dump_json(indent=2))
