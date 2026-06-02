"""API FastAPI pour RedSimulator.

Expose le pipeline via Server-Sent Events (SSE) pour permettre
au frontend React d'afficher la progression en temps reel.

Usage:
    .venv/bin/uvicorn src.api:app --reload --port 8080

Endpoints:
    GET  /api/health          — Health check
    GET  /api/scan/stream     — SSE : pipeline live contre une cible
    GET  /api/scan/fixtures   — SSE : pipeline avec fixtures
    POST /api/chat            — Question au chatbot RAG
"""

import asyncio
import ipaddress
import json
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from src.infra.config import settings
from src.infra.exceptions import RedSimulatorError
from src.infra.logging import get_logger, setup_logging

ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(ENV_PATH, override=True)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Pipeline state
# ---------------------------------------------------------------------------


class _PipelineState:
    """Holds mutable state shared across API endpoints.

    NOTE: This is NOT thread-safe.  It is acceptable for a single-process
    uvicorn deployment where SSE handlers run on the async event loop.
    If the API is ever served with multiple workers, this must be replaced
    by a proper shared store (e.g. Redis).
    """

    def __init__(self) -> None:
        self.last_report: str = ""
        self.is_fixtures: bool = False
        # Keep pipeline results for knowledge-graph construction in the RAG chatbot
        self.last_scan = None  # ScanResult | None
        self.last_plan = None  # AttackPlan | None
        self.last_results = None  # AttackResult | None


_state = _PipelineState()


# ---------------------------------------------------------------------------
# Target URL validation
# ---------------------------------------------------------------------------

# Internal / private IP ranges that must be blocked (SSRF protection).
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# 127.x.x.x except 127.0.0.1 (localhost:3000 is allowed for local dev)
_LOOPBACK_NETWORK = ipaddress.ip_network("127.0.0.0/8")
_ALLOWED_LOOPBACK = ipaddress.ip_address("127.0.0.1")


def _validate_target_url(url: str) -> str | None:
    """Validate that *url* is an acceptable scan target.

    Returns None if valid, or an error message string if invalid.
    """
    if not url.startswith(("http://", "https://")):
        return "Target URL must start with http:// or https://"

    try:
        parsed = urlparse(url)
    except Exception:
        return "Target URL is malformed"

    hostname = parsed.hostname
    if not hostname:
        return "Target URL must include a hostname"

    # Resolve hostname to IP for internal-range check
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # hostname is a DNS name, not a raw IP — allow it
        # (DNS rebinding is out of scope for this PoC)
        return None

    # Allow localhost (127.0.0.1) for local dev
    if addr in _LOOPBACK_NETWORK and addr != _ALLOWED_LOOPBACK:
        return "Target URL points to a blocked loopback address"

    for network in _INTERNAL_NETWORKS:
        if addr in network:
            return f"Target URL points to a blocked internal network ({network})"

    return None


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown logic."""
    setup_logging(settings.log_level, settings.log_format)
    logger.info("RedSimulator API starting up")
    yield
    # Shutdown: close Playwright cleanly
    try:
        from src.scanner.browser import shutdown

        shutdown()
    except Exception:
        pass
    logger.info("RedSimulator API shut down")


app = FastAPI(title="RedSimulator API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------


def _sse(event_type: str, data: dict):
    """Formate un evenement SSE."""
    return {"event": event_type, "data": json.dumps(data, default=str)}


def _safe_error_payload(phase: str, exc: Exception) -> dict:
    """Build an SSE error payload that never leaks raw exception details."""
    if isinstance(exc, RedSimulatorError):
        payload = exc.to_safe_dict()
        payload["phase"] = phase
        return payload
    logger.error("Unexpected error in phase %s", phase, exc_info=exc)
    return {"phase": phase, "error": "INTERNAL_ERROR", "message": "An unexpected error occurred"}


# ---------------------------------------------------------------------------
# SSE pipeline generator
# ---------------------------------------------------------------------------


async def _run_pipeline(target: str, use_fixtures: bool):
    """Generateur SSE avec delais pour affichage temps reel."""
    _state.is_fixtures = use_fixtures
    fixtures_dir = Path(__file__).parent.parent / "data" / "fixtures"

    # ── ETAPE 1 : SCANNER ──
    yield _sse("phase", {"phase": "scanning", "label": "Scanner — Reconnaissance"})
    await asyncio.sleep(0.3)

    try:
        if use_fixtures:
            from src.scanner.agent import ReconAgent

            scan_result = ReconAgent.from_fixture()
            yield _sse("scan_log", {"text": "Chargement de la fixture scan_result.json..."})
            await asyncio.sleep(0.2)
            yield _sse(
                "scan_log", {"text": f"Fixture chargee — {len(scan_result.endpoints)} endpoints"}
            )
            await asyncio.sleep(0.2)
        else:
            from src.scanner.agent import ReconAgent

            # Queue pour streamer les evenements en temps reel
            queue: asyncio.Queue = asyncio.Queue()
            loop = asyncio.get_event_loop()

            def on_event(event_type: str, data: dict):
                """Callback appele depuis le thread de l'agent."""
                loop.call_soon_threadsafe(queue.put_nowait, (event_type, data))

            agent = ReconAgent(target, on_event=on_event)

            # Lancer le scan dans un thread pour ne pas bloquer l'async
            scan_result_container = [None]
            scan_error_container = [None]

            def run_scan():
                try:
                    scan_result_container[0] = agent.run()
                except Exception as e:
                    scan_error_container[0] = e
                finally:
                    loop.call_soon_threadsafe(queue.put_nowait, ("__done__", {}))

            thread = threading.Thread(target=run_scan, daemon=True)
            thread.start()

            # Lire la queue et streamer les evenements SSE
            while True:
                event_type, data = await queue.get()
                if event_type == "__done__":
                    break
                yield _sse(event_type, data)
                await asyncio.sleep(0.05)

            if scan_error_container[0]:
                raise scan_error_container[0]

            scan_result = scan_result_container[0]

            # Les agent_steps ont deja ete emis en temps reel via la queue

        # Resultats globaux
        scan_data = json.loads(scan_result.model_dump_json())
        yield _sse(
            "scan_result",
            {
                "ports": len(scan_data["open_ports"]),
                "endpoints": len(scan_data["endpoints"]),
                "forms": len(scan_data["forms"]),
                "technologies": scan_data["technologies"],
                "missing_headers": scan_data["headers"]["missing_security_headers"],
            },
        )
        await asyncio.sleep(0.2)

        # Ports un par un
        for port in scan_data["open_ports"]:
            yield _sse("port", port)
            await asyncio.sleep(0.15)

        # Endpoints un par un
        for ep in scan_data["endpoints"]:
            yield _sse("endpoint", ep)
            await asyncio.sleep(0.08)

        # Technologies
        for tech in scan_data["technologies"]:
            yield _sse("technology", {"name": tech})
            await asyncio.sleep(0.2)

        # Headers manquants
        for h in scan_data["headers"]["missing_security_headers"]:
            yield _sse("missing_header", {"name": h})
            await asyncio.sleep(0.15)

        # Formulaires un par un
        for form in scan_data["forms"]:
            yield _sse("form", form)
            await asyncio.sleep(0.2)

        yield _sse("phase_done", {"phase": "scanning"})
        await asyncio.sleep(0.5)

    except Exception as e:
        yield _sse("error", _safe_error_payload("scanning", e))
        return

    # ── ETAPE 2 : EXPERT ──
    yield _sse("phase", {"phase": "expert", "label": "Systeme Expert — Analyse"})
    await asyncio.sleep(0.3)

    try:
        if use_fixtures:
            data = json.loads((fixtures_dir / "attack_plan.json").read_text())
            from src.models import AttackPlan

            attack_plan = AttackPlan.model_validate(data)
        else:
            from src.expert.engine import ExpertEngine
            from src.expert.facts import scan_result_to_facts
            from src.expert.rules import get_all_rules

            facts = scan_result_to_facts(scan_result)
            engine = ExpertEngine()
            engine.inject_facts(facts)
            engine.load_rules(get_all_rules())
            attack_plan = engine.run()

        # Regles activees une par une
        for rule in attack_plan.rules_fired:
            yield _sse("rule_fired", {"rule": rule})
            await asyncio.sleep(0.3)

        # Vecteurs un par un
        for v in attack_plan.vectors:
            v_data = json.loads(v.model_dump_json())
            yield _sse("vector", v_data)
            await asyncio.sleep(0.5)

        yield _sse(
            "expert_result",
            {
                "vectors": len(attack_plan.vectors),
                "rules_fired": attack_plan.rules_fired,
            },
        )
        yield _sse("phase_done", {"phase": "expert"})
        await asyncio.sleep(0.5)

    except Exception as e:
        yield _sse("error", _safe_error_payload("expert", e))
        return

    # ── ETAPE 3 : GENERATOR ──
    yield _sse("phase", {"phase": "generator", "label": "Generator — Mutations"})
    await asyncio.sleep(0.3)

    try:
        from src.models import PayloadResult

        if use_fixtures:
            data = json.loads((fixtures_dir / "payload_result.json").read_text())
            payload_result = PayloadResult.model_validate(data)
        else:
            from src.generator.generate import generate_for_plan

            payload_result = generate_for_plan(attack_plan)

        for p in payload_result.payloads:
            p_data = json.loads(p.model_dump_json())
            yield _sse("payload", p_data)
            await asyncio.sleep(0.25)

        yield _sse("generator_result", {"payloads": len(payload_result.payloads)})
        yield _sse("phase_done", {"phase": "generator"})
        await asyncio.sleep(0.5)

    except Exception as e:
        yield _sse("error", _safe_error_payload("generator", e))
        return

    # ── ETAPE 4 : EXECUTOR ──
    yield _sse("phase", {"phase": "attacking", "label": "Executor — Attaques"})
    await asyncio.sleep(0.3)

    try:
        from src.models import AttackResult

        if use_fixtures:
            data = json.loads((fixtures_dir / "attack_result.json").read_text())
            attack_result = AttackResult.model_validate(data)
        else:
            from src.executor.runner import AttackExecutor

            executor = AttackExecutor(target)
            attack_result = executor.execute_all(attack_plan, payload_result)

        for a in attack_result.results:
            a_data = json.loads(a.model_dump_json())
            yield _sse("attack", a_data)
            await asyncio.sleep(0.3)

        yield _sse(
            "executor_result",
            {
                "total": attack_result.total_attempts,
                "successful": attack_result.successful_attacks,
            },
        )
        yield _sse("phase_done", {"phase": "attacking"})
        await asyncio.sleep(0.5)

    except Exception as e:
        yield _sse("error", _safe_error_payload("attacking", e))
        return

    # ── ETAPE 5 : REPORTER ──
    yield _sse("phase", {"phase": "reporting", "label": "Reporter — Generation"})
    await asyncio.sleep(0.3)

    try:
        from src.reporter.report_generator import generate_report

        report = generate_report(scan_result, attack_plan, attack_result)
        _state.last_report = report
        _state.last_scan = scan_result
        _state.last_plan = attack_plan
        _state.last_results = attack_result

        # Rapport par petits chunks pour effet typewriter
        chunk_size = 40
        for i in range(0, len(report), chunk_size):
            yield _sse("report_chunk", {"text": report[i : i + chunk_size]})
            await asyncio.sleep(0.02)

        yield _sse("phase_done", {"phase": "reporting"})
        await asyncio.sleep(0.3)

    except Exception as e:
        yield _sse("error", _safe_error_payload("reporting", e))
        return

    yield _sse("pipeline_done", {"message": "Pipeline termine"})


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(UTC).isoformat()}


@app.get("/api/scan/stream")
async def scan_stream(target: str = Query(default="http://localhost:3000")):
    """Pipeline live via SSE."""
    error = _validate_target_url(target)
    if error:
        logger.warning("Rejected scan target %r: %s", target, error)
        return JSONResponse(status_code=400, content={"error": "INVALID_TARGET", "message": error})
    return EventSourceResponse(_run_pipeline(target, use_fixtures=False))


@app.get("/api/scan/fixtures")
async def scan_fixtures():
    """Pipeline fixtures via SSE."""
    return EventSourceResponse(_run_pipeline("http://localhost:3000", use_fixtures=True))


class ChatRequest(BaseModel):
    question: str


@app.post("/api/chat")
def chat(req: ChatRequest):
    """Question au chatbot RAG."""
    if not _state.last_report:
        return {"answer": "Aucun rapport disponible. Lancez d'abord un scan.", "mode": "error"}

    # En mode fixtures, reponse generique sans appeler le RAG
    if _state.is_fixtures:
        return {
            "answer": "Le chatbot RAG est disponible uniquement en mode live. "
            "En mode fixtures, les donnees sont simulees et le RAG n'est pas active. "
            "Lancez un scan reel pour utiliser le chatbot.",
            "mode": "fixtures",
        }

    try:
        from src.reporter.rag import ask_report, index_report

        index_report(
            _state.last_report,
            scan=_state.last_scan,
            plan=_state.last_plan,
            results=_state.last_results,
        )
        answer = ask_report(req.question)
        return {"answer": answer, "mode": "live"}
    except RedSimulatorError as exc:
        logger.error("RAG chatbot error: %s", exc, exc_info=exc)
        return {"answer": "Une erreur est survenue lors du traitement.", "mode": "error"}
    except Exception as exc:
        logger.error("Unexpected RAG chatbot error", exc_info=exc)
        return {"answer": "Une erreur est survenue lors du traitement.", "mode": "error"}
