"""API FastAPI pour RedSimulator.

Expose le pipeline via Server-Sent Events (SSE) pour permettre
au frontend React d'afficher la progression en temps reel.

Usage:
    .venv/bin/uvicorn src.api:app --reload --port 8080

Endpoints:
    GET  /api/health                    — Health check
    GET  /api/scan/stream               — SSE : pipeline live contre une cible
    GET  /api/scan/fixtures             — SSE : pipeline avec fixtures
    POST /api/chat                      — Question au chatbot RAG
    GET  /api/dashboard/targets         — List all scanned targets
    GET  /api/dashboard/history/{target}— Scan history for a target
    GET  /api/dashboard/trends/{target} — Trend data for a target
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
    # Clear sensitive data on shutdown
    from src.infra.llm_config import llm_config

    llm_config.clear()
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
    import time as _time

    _state.is_fixtures = use_fixtures
    fixtures_dir = Path(__file__).parent.parent / "data" / "fixtures"
    pipeline_start = _time.perf_counter()
    cvss_scores: list[dict] = []

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

        # Compute CVSS scores for each vector
        from src.scoring import attack_type_to_cvss, calculate_cvss_score

        for v in attack_plan.vectors:
            cvss_vec = attack_type_to_cvss(v.attack_type.value)
            score, severity = calculate_cvss_score(cvss_vec)
            cvss_entry = {
                "vector_id": v.id,
                "score": score,
                "severity": severity,
                "vector_string": cvss_vec.to_vector_string(),
            }
            cvss_scores.append(cvss_entry)
            yield _sse("cvss_score", cvss_entry)
            await asyncio.sleep(0.2)

        yield _sse(
            "expert_result",
            {
                "vectors": len(attack_plan.vectors),
                "rules_fired": attack_plan.rules_fired,
                "cvss_scores": cvss_scores,
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

        report = generate_report(
            scan_result,
            attack_plan,
            attack_result,
            cvss_scores=cvss_scores,
        )
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

    # Record dashboard snapshot
    try:
        import uuid as _uuid

        from src.dashboard import DashboardStore, ScanSnapshot
        from src.reporter.report_generator import _compute_risk_score

        duration_ms = (_time.perf_counter() - pipeline_start) * 1000

        severity_counts: dict[str, int] = {}
        for v in attack_plan.vectors:
            sev = v.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        success_rate = (
            attack_result.successful_attacks / attack_result.total_attempts
            if attack_result.total_attempts > 0
            else 0.0
        )
        risk_score = _compute_risk_score(severity_counts, success_rate)
        attack_types = sorted({v.attack_type.value for v in attack_plan.vectors})

        snapshot = ScanSnapshot(
            id=str(_uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            target=target,
            total_vectors=len(attack_plan.vectors),
            total_attempts=attack_result.total_attempts,
            successful_attacks=attack_result.successful_attacks,
            severity_counts=severity_counts,
            attack_types=attack_types,
            rules_fired=len(attack_plan.rules_fired),
            cvss_scores=cvss_scores,
            risk_score=risk_score,
            duration_ms=duration_ms,
        )

        db_path = str(Path(__file__).parent.parent / "data" / "dashboard" / "history.db")
        store = DashboardStore(db_path=db_path)
        store.record_scan(snapshot)
        store.close()

        yield _sse(
            "dashboard_recorded",
            {
                "snapshot_id": snapshot.id,
                "risk_score": risk_score,
            },
        )
    except Exception as e:
        logger.warning("Failed to record dashboard snapshot via SSE: %s", e)

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


class CampaignRequest(BaseModel):
    targets: list[str]
    name: str = "API Campaign"
    parallel: bool = False
    max_parallel: int = 3
    use_fixtures: bool = False


@app.post("/api/campaign/run")
async def run_campaign(req: CampaignRequest):
    """Run a campaign against multiple targets (SSE streaming).

    Sends progress events for each target as they are scanned, followed
    by a final summary event when the campaign completes.
    """
    # Validate every target URL
    for url in req.targets:
        error = _validate_target_url(url)
        if error:
            logger.warning("Rejected campaign target %r: %s", url, error)
            return JSONResponse(
                status_code=400,
                content={"error": "INVALID_TARGET", "message": f"{url}: {error}"},
            )

    if not req.targets:
        return JSONResponse(
            status_code=400,
            content={"error": "NO_TARGETS", "message": "At least one target URL is required"},
        )

    async def _campaign_sse():
        from src.campaign.manager import CampaignManager
        from src.campaign.models import CampaignConfig, TargetConfig

        targets = [TargetConfig(url=url) for url in req.targets]
        config = CampaignConfig(
            name=req.name,
            targets=targets,
            parallel=req.parallel,
            max_parallel=req.max_parallel,
            use_fixtures=req.use_fixtures,
        )

        manager = CampaignManager(config)

        # Progress queue bridges synchronous callbacks to async SSE
        progress_queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def on_progress(target_name: str, status: str, detail: str):
            loop.call_soon_threadsafe(
                progress_queue.put_nowait,
                {"target": target_name, "status": status, "detail": detail},
            )

        # Run the campaign in a background thread
        result_container = [None]
        error_container = [None]

        def run():
            try:
                result_container[0] = manager.run(on_progress=on_progress)
            except Exception as e:
                error_container[0] = e
            finally:
                loop.call_soon_threadsafe(progress_queue.put_nowait, None)  # sentinel

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

        yield _sse(
            "campaign_start",
            {
                "name": config.name,
                "targets": [t.url for t in config.targets],
                "parallel": config.parallel,
            },
        )

        # Stream progress events until the campaign finishes
        while True:
            item = await progress_queue.get()
            if item is None:
                break
            yield _sse("campaign_progress", item)
            await asyncio.sleep(0.05)

        if error_container[0]:
            yield _sse("error", _safe_error_payload("campaign", error_container[0]))
            return

        result = result_container[0]

        # Per-target result events
        for tr in result.results:
            tr_data = {
                "target": tr.target.url,
                "name": tr.target.name,
                "status": tr.status,
                "error": tr.error,
                "duration_ms": tr.duration_ms,
                "attack_summary": {
                    "total_attempts": (
                        tr.attack_result.get("total_attempts", 0) if tr.attack_result else 0
                    ),
                    "successful_attacks": (
                        tr.attack_result.get("successful_attacks", 0) if tr.attack_result else 0
                    ),
                },
            }
            yield _sse("campaign_target_result", tr_data)
            await asyncio.sleep(0.1)

        # Campaign report
        report = manager.generate_campaign_report()
        chunk_size = 80
        for i in range(0, len(report), chunk_size):
            yield _sse("campaign_report_chunk", {"text": report[i : i + chunk_size]})
            await asyncio.sleep(0.02)

        # Final summary
        yield _sse(
            "campaign_done",
            {
                "status": result.status,
                "summary": result.summary,
            },
        )

    return EventSourceResponse(_campaign_sse())


# ---------------------------------------------------------------------------
# Pentester agent SSE endpoint
# ---------------------------------------------------------------------------


async def _run_pentest(target: str):
    """SSE generator for the autonomous pentester agent."""
    yield _sse(
        "pentest_start",
        {
            "target": target,
            "message": "Starting autonomous pentest agent...",
        },
    )
    await asyncio.sleep(0.2)

    # Queue to bridge synchronous agent callbacks to async SSE
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def on_event(event_type: str, data: dict):
        """Callback called from the agent thread."""
        loop.call_soon_threadsafe(queue.put_nowait, (event_type, data))

    from src.pentester.agent import PentesterAgent

    agent = PentesterAgent(target, on_event=on_event)

    # Run the agent in a background thread to avoid blocking async
    result_container = [None]
    error_container = [None]

    def run_pentest():
        try:
            result_container[0] = agent.run(max_iterations=30)
        except Exception as e:
            error_container[0] = e
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, ("__done__", {}))

    thread = threading.Thread(target=run_pentest, daemon=True)
    thread.start()

    # Stream events from the queue
    while True:
        event_type, data = await queue.get()
        if event_type == "__done__":
            break
        yield _sse(event_type, data)
        await asyncio.sleep(0.05)

    if error_container[0]:
        yield _sse("pentest_error", _safe_error_payload("pentest", error_container[0]))
        return

    result = result_container[0]
    if result:
        # Send the final result
        yield _sse(
            "pentest_result",
            {
                "findings": result.get("findings", []),
                "attack_chains": result.get("attack_chains", []),
                "recommendations": result.get("recommendations", []),
                "metadata": result.get("metadata", {}),
            },
        )

    yield _sse(
        "pentest_done",
        {
            "message": "Autonomous pentest complete",
            "findings_count": len(result.get("findings", [])) if result else 0,
        },
    )


@app.get("/api/pentest/stream")
async def pentest_stream(target: str = Query(default="http://localhost:3000")):
    """Run the autonomous pentester agent with SSE streaming.

    The agent autonomously performs reconnaissance, vulnerability analysis,
    exploitation, post-exploitation, and reporting. All reasoning is
    streamed in real-time.

    Events emitted:
        - pentest_start: Agent is starting
        - pentest_phase: Phase change (recon, exploitation, post-exploit, reporting)
        - agent_reasoning: Agent's thinking (observation, decision, finding)
        - agent_action: Tool being called with arguments
        - agent_finding: Confirmed vulnerability
        - agent_tool_result: Tool execution result
        - pentest_result: Final report with all findings
        - pentest_done: Agent finished
        - pentest_error: Error occurred
    """
    error = _validate_target_url(target)
    if error:
        logger.warning("Rejected pentest target %r: %s", target, error)
        return JSONResponse(status_code=400, content={"error": "INVALID_TARGET", "message": error})
    return EventSourceResponse(_run_pentest(target))


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


# ---------------------------------------------------------------------------
# LLM Settings endpoints
# ---------------------------------------------------------------------------


class LLMConfigRequest(BaseModel):
    provider: str  # "anthropic", "ollama", "openai"
    model: str
    api_key: str = ""  # Only for cloud providers -- NEVER stored on disk
    ollama_url: str = ""  # Only for ollama


@app.post("/api/settings/llm")
async def configure_llm(config: LLMConfigRequest):
    """Configure the LLM provider at runtime.

    The API key is stored in memory only -- it is NEVER persisted to disk,
    NEVER logged, and NEVER returned in any API response.
    """
    from src.infra.llm_config import llm_config

    result = llm_config.configure(
        provider=config.provider,
        model=config.model,
        api_key=config.api_key,
        ollama_url=config.ollama_url,
    )
    # result already excludes the API key
    return result


@app.get("/api/settings/llm")
async def get_llm_config():
    """Get current LLM configuration (API key is NEVER included)."""
    from src.infra.llm_config import llm_config

    config = llm_config.get_safe_dict()

    # Add available providers and their models
    config["available_providers"] = [
        {"id": "anthropic", "name": "Anthropic (Claude)", "requires_key": True},
        {"id": "ollama", "name": "Ollama (Local)", "requires_key": False},
        {"id": "openai", "name": "OpenAI", "requires_key": True},
    ]

    # Model suggestions per provider
    config["suggested_models"] = {
        "anthropic": [
            "claude-sonnet-4-20250514",
            "claude-haiku-4-20250514",
        ],
        "ollama": _get_ollama_models(),
        "openai": [
            "gpt-4o",
            "gpt-4o-mini",
        ],
    }
    return config


@app.delete("/api/settings/llm")
async def clear_llm_config():
    """Clear LLM configuration and API key from memory."""
    from src.infra.llm_config import llm_config

    llm_config.clear()
    return {"status": "cleared"}


def _get_ollama_models() -> list[str]:
    """Fetch available models from the local Ollama instance."""
    try:
        import requests

        from src.infra.llm_config import llm_config

        runtime = llm_config.get_config()
        ollama_url = runtime.ollama_url if runtime.configured else settings.ollama_url
        resp = requests.get(f"{ollama_url}/api/tags", timeout=3)
        if resp.status_code == 200:
            return [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Custom Rules API
# ---------------------------------------------------------------------------


@app.get("/api/rules")
async def list_rules():
    """List all rules (built-in + custom).

    Returns built-in rule names and all custom rule definitions.
    """
    from src.expert.custom_rules import CustomRuleEngine
    from src.expert.rules import get_all_rules

    try:
        # Built-in rules (just names and priorities)
        all_rules = get_all_rules()
        builtin = [
            {"name": r.name, "priority": r.priority, "type": "builtin"}
            for r in all_rules
            if not r.name.startswith("CUSTOM:")
        ]

        # Custom rules (full definitions)
        engine = CustomRuleEngine()
        custom = [{**rd.to_dict(), "type": "custom"} for rd in engine.list_rules()]

        return {"rules": builtin + custom, "total": len(builtin) + len(custom)}
    except Exception as exc:
        logger.error("Failed to list rules", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "RULES_LIST_FAILED", "message": str(exc)},
        )


@app.get("/api/rules/custom")
async def list_custom_rules():
    """List user-defined custom rules."""
    from src.expert.custom_rules import CustomRuleEngine

    try:
        engine = CustomRuleEngine()
        rules = engine.list_rules()
        return {
            "rules": [r.to_dict() for r in rules],
            "total": len(rules),
        }
    except Exception as exc:
        logger.error("Failed to list custom rules", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "CUSTOM_RULES_LIST_FAILED", "message": str(exc)},
        )


@app.post("/api/rules/custom")
async def create_custom_rule(rule: dict):
    """Create a new custom rule from JSON definition.

    The rule is defined declaratively (no Python code). See the
    CustomRuleDefinition docstring for the condition/action formats.
    """
    from src.expert.custom_rules import CustomRuleDefinition, CustomRuleEngine

    try:
        defn = CustomRuleDefinition.from_dict(rule)
        engine = CustomRuleEngine()
        engine.save_rule(defn)
        return {"status": "created", "rule": defn.to_dict()}
    except (ValueError, KeyError) as exc:
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_RULE", "message": str(exc)},
        )
    except Exception as exc:
        logger.error("Failed to create custom rule", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "CUSTOM_RULE_CREATE_FAILED", "message": str(exc)},
        )


@app.delete("/api/rules/custom/{name}")
async def delete_custom_rule(name: str):
    """Delete a custom rule by name."""
    from src.expert.custom_rules import CustomRuleEngine

    try:
        engine = CustomRuleEngine()
        deleted = engine.delete_rule(name)
        if not deleted:
            return JSONResponse(
                status_code=404,
                content={"error": "RULE_NOT_FOUND", "message": f"Custom rule '{name}' not found"},
            )
        return {"status": "deleted", "name": name}
    except Exception as exc:
        logger.error("Failed to delete custom rule", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "CUSTOM_RULE_DELETE_FAILED", "message": str(exc)},
        )


@app.put("/api/rules/custom/{name}/toggle")
async def toggle_custom_rule(name: str):
    """Enable/disable a custom rule."""
    from src.expert.custom_rules import CustomRuleEngine

    try:
        engine = CustomRuleEngine()
        new_state = engine.toggle_rule(name)
        if new_state is None:
            return JSONResponse(
                status_code=404,
                content={"error": "RULE_NOT_FOUND", "message": f"Custom rule '{name}' not found"},
            )
        return {"status": "toggled", "name": name, "enabled": new_state}
    except Exception as exc:
        logger.error("Failed to toggle custom rule", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "CUSTOM_RULE_TOGGLE_FAILED", "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# Proxy endpoints
# ---------------------------------------------------------------------------

# Check whether mitmproxy is installed at import time so endpoints can
# return 501 immediately if it is missing.
try:
    import mitmproxy  # noqa: F401

    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

_proxy_server = None  # ProxyServer | None — lazy singleton
_flow_store = None  # FlowStore | None — lazy singleton


def _get_flow_store():
    """Return (or create) the shared FlowStore singleton."""
    global _flow_store
    if _flow_store is None:
        from src.proxy.store import FlowStore

        _flow_store = FlowStore()
    return _flow_store


def _require_mitmproxy():
    """Return a JSONResponse(501) if mitmproxy is not installed, else None."""
    if not MITMPROXY_AVAILABLE:
        return JSONResponse(
            status_code=501,
            content={
                "error": "MITMPROXY_NOT_AVAILABLE",
                "message": (
                    "mitmproxy is not installed. Install it with: pip install mitmproxy>=10.0"
                ),
            },
        )
    return None


@app.post("/api/proxy/start")
async def proxy_start():
    """Start the MITM proxy."""
    unavailable = _require_mitmproxy()
    if unavailable:
        return unavailable

    global _proxy_server
    try:
        if _proxy_server is not None and getattr(_proxy_server, "running", False):
            return JSONResponse(
                status_code=409,
                content={"error": "ALREADY_RUNNING", "message": "Proxy is already running"},
            )

        from src.proxy.server import ProxyServer

        store = _get_flow_store()
        _proxy_server = ProxyServer(store=store)
        _proxy_server.start()

        return {
            "status": "started",
            "host": getattr(_proxy_server, "host", "127.0.0.1"),
            "port": getattr(_proxy_server, "port", 8888),
        }
    except Exception as exc:
        logger.error("Failed to start proxy", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "PROXY_START_FAILED", "message": str(exc)},
        )


@app.post("/api/proxy/stop")
async def proxy_stop():
    """Stop the MITM proxy."""
    global _proxy_server
    try:
        if _proxy_server is None or not getattr(_proxy_server, "running", False):
            return JSONResponse(
                status_code=409,
                content={"error": "NOT_RUNNING", "message": "Proxy is not running"},
            )

        _proxy_server.stop()
        return {"status": "stopped"}
    except Exception as exc:
        logger.error("Failed to stop proxy", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "PROXY_STOP_FAILED", "message": str(exc)},
        )


@app.get("/api/proxy/status")
async def proxy_status():
    """Get proxy status."""
    try:
        store = _get_flow_store()
        running = _proxy_server is not None and getattr(_proxy_server, "running", False)
        return {
            "running": running,
            "available": MITMPROXY_AVAILABLE,
            "flows_count": store.count(),
            "host": getattr(_proxy_server, "host", "127.0.0.1") if _proxy_server else "127.0.0.1",
            "port": getattr(_proxy_server, "port", 8888) if _proxy_server else 8888,
        }
    except Exception as exc:
        logger.error("Failed to get proxy status", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "PROXY_STATUS_FAILED", "message": str(exc)},
        )


@app.get("/api/proxy/flows")
async def proxy_flows(
    url_pattern: str = Query(default=""),
    method: str = Query(default=""),
    status_min: int = Query(default=0),
    status_max: int = Query(default=999),
    limit: int = Query(default=50),
    offset: int = Query(default=0),
):
    """List captured flows with filtering."""
    try:
        store = _get_flow_store()
        flows = store.search(
            url_pattern=url_pattern,
            method=method,
            status_min=status_min,
            status_max=status_max,
            limit=limit,
            offset=offset,
        )
        return {
            "flows": [f.to_dict() for f in flows],
            "total": store.count(),
            "limit": limit,
            "offset": offset,
        }
    except Exception as exc:
        logger.error("Failed to list proxy flows", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "PROXY_FLOWS_FAILED", "message": str(exc)},
        )


@app.get("/api/proxy/flows/stream")
async def proxy_flows_stream():
    """SSE stream of new captured flows."""

    async def _flow_event_generator():
        queue: asyncio.Queue = asyncio.Queue()

        # Register the queue as a listener on the proxy server
        if _proxy_server is not None and hasattr(_proxy_server, "add_flow_listener"):
            _proxy_server.add_flow_listener(queue)

        try:
            while True:
                try:
                    flow_dict = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield _sse("flow", flow_dict)
                except TimeoutError:
                    # Send keep-alive comment to prevent connection timeout
                    yield {"comment": "keep-alive"}
        finally:
            if _proxy_server is not None and hasattr(_proxy_server, "remove_flow_listener"):
                _proxy_server.remove_flow_listener(queue)

    return EventSourceResponse(_flow_event_generator())


@app.get("/api/proxy/flows/{flow_id}")
async def proxy_flow_detail(flow_id: str):
    """Get a single flow's full details."""
    try:
        store = _get_flow_store()
        flow = store.get(flow_id)
        if flow is None:
            return JSONResponse(
                status_code=404,
                content={"error": "FLOW_NOT_FOUND", "message": f"Flow {flow_id} not found"},
            )
        return flow.to_dict()
    except Exception as exc:
        logger.error("Failed to get flow detail", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "PROXY_FLOW_DETAIL_FAILED", "message": str(exc)},
        )


@app.post("/api/proxy/flows/{flow_id}/replay")
async def proxy_flow_replay(flow_id: str):
    """Replay a captured flow."""
    try:
        store = _get_flow_store()
        flow = store.get(flow_id)
        if flow is None:
            return JSONResponse(
                status_code=404,
                content={"error": "FLOW_NOT_FOUND", "message": f"Flow {flow_id} not found"},
            )

        try:
            from src.proxy.replayer import FlowReplayer

            replayer = FlowReplayer()
            new_flow = replayer.replay(flow)
            store.add(new_flow)
            return new_flow.to_dict()
        except ImportError:
            # FlowReplayer not yet available — replay with basic httpx/requests
            return JSONResponse(
                status_code=501,
                content={
                    "error": "REPLAYER_NOT_AVAILABLE",
                    "message": "FlowReplayer module is not available yet",
                },
            )
    except Exception as exc:
        logger.error("Failed to replay flow", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "PROXY_REPLAY_FAILED", "message": str(exc)},
        )


@app.post("/api/proxy/feed")
async def proxy_feed(host: str = Query(default="")):
    """Convert captured flows to ScanResult and run pipeline."""
    try:
        store = _get_flow_store()
        flows = store.search(url_pattern=host, limit=500)
        if not flows:
            return JSONResponse(
                status_code=404,
                content={"error": "NO_FLOWS", "message": "No captured flows to feed"},
            )

        try:
            from src.proxy.adapter import ProxyFeedAdapter

            adapter = ProxyFeedAdapter()
            scan_result = adapter.to_scan_result(flows)
        except ImportError:
            # ProxyFeedAdapter not yet available — build a minimal ScanResult
            from src.scanner.agent import ReconAgent

            scan_result = ReconAgent.from_fixture()
            logger.warning("ProxyFeedAdapter not available, using fixture scan result")

        _state.last_scan = scan_result
        return {
            "status": "fed",
            "endpoints": len(scan_result.endpoints) if hasattr(scan_result, "endpoints") else 0,
            "flows_used": len(flows),
        }
    except Exception as exc:
        logger.error("Failed to feed proxy flows", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "PROXY_FEED_FAILED", "message": str(exc)},
        )


@app.delete("/api/proxy/flows")
async def proxy_flows_clear():
    """Clear all captured flows."""
    try:
        store = _get_flow_store()
        deleted = store.clear()
        return {"deleted": deleted}
    except Exception as exc:
        logger.error("Failed to clear proxy flows", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "PROXY_CLEAR_FAILED", "message": str(exc)},
        )


@app.get("/api/proxy/export/har")
async def proxy_export_har():
    """Export flows as HAR file."""
    try:
        store = _get_flow_store()
        har = store.export_har()
        return JSONResponse(content=har, media_type="application/json")
    except Exception as exc:
        logger.error("Failed to export HAR", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "PROXY_EXPORT_FAILED", "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# Dashboard endpoints
# ---------------------------------------------------------------------------

_dashboard_store = None  # DashboardStore | None — lazy singleton


def _get_dashboard_store():
    """Return (or create) the shared DashboardStore singleton."""
    global _dashboard_store
    if _dashboard_store is None:
        from src.dashboard import DashboardStore

        db_path = str(Path(__file__).parent.parent / "data" / "dashboard" / "history.db")
        _dashboard_store = DashboardStore(db_path=db_path)
    return _dashboard_store


@app.get("/api/dashboard/targets")
async def dashboard_targets():
    """List all targets with their latest scan info."""
    try:
        store = _get_dashboard_store()
        targets = store.get_all_targets()
        result = []
        for target in targets:
            latest = store.get_latest(target)
            if latest:
                result.append(
                    {
                        "target": target,
                        "last_scan": latest.timestamp,
                        "risk_score": latest.risk_score,
                        "total_vectors": latest.total_vectors,
                        "successful_attacks": latest.successful_attacks,
                        "severity_counts": latest.severity_counts,
                    }
                )
        return {"targets": result}
    except Exception as exc:
        logger.error("Failed to list dashboard targets", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "DASHBOARD_TARGETS_FAILED", "message": str(exc)},
        )


@app.get("/api/dashboard/history/{target:path}")
async def dashboard_history(target: str, limit: int = Query(default=50)):
    """Get scan history for a target."""
    try:
        store = _get_dashboard_store()
        snapshots = store.get_history(target, limit=limit)
        return {
            "target": target,
            "count": len(snapshots),
            "snapshots": [
                {
                    "id": s.id,
                    "timestamp": s.timestamp,
                    "total_vectors": s.total_vectors,
                    "total_attempts": s.total_attempts,
                    "successful_attacks": s.successful_attacks,
                    "severity_counts": s.severity_counts,
                    "attack_types": s.attack_types,
                    "rules_fired": s.rules_fired,
                    "cvss_scores": s.cvss_scores,
                    "risk_score": s.risk_score,
                    "duration_ms": s.duration_ms,
                }
                for s in snapshots
            ],
        }
    except Exception as exc:
        logger.error("Failed to get dashboard history", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "DASHBOARD_HISTORY_FAILED", "message": str(exc)},
        )


@app.get("/api/dashboard/trends/{target:path}")
async def dashboard_trends(target: str):
    """Get trend data for a target."""
    try:
        store = _get_dashboard_store()
        trend = store.get_trend(target)
        return {
            "target": target,
            "total_scans": len(trend.snapshots),
            "risk_trend": trend.risk_trend,
            "vuln_trend": trend.vuln_trend,
            "success_rate_trend": trend.success_rate_trend,
            "severity_trend": trend.severity_trend,
        }
    except Exception as exc:
        logger.error("Failed to get dashboard trends", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "DASHBOARD_TRENDS_FAILED", "message": str(exc)},
        )
