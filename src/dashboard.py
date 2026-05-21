"""Dashboard Streamlit pour RedSimulator.

Interface du pipeline de securite automatise avec progression en temps reel.
"""

import json
import time
import threading
from pathlib import Path
from io import StringIO
from contextlib import redirect_stdout

import streamlit as st
import plotly.graph_objects as go

st.set_page_config(page_title="RedSimulator", page_icon="RS", layout="wide")

st.markdown("""
<style>
    .step-think { border-left: 3px solid #4a90d9; background: #f0f4ff; padding: 8px 12px; margin: 3px 0; border-radius: 0 4px 4px 0; font-size: 0.88em; }
    .step-act { border-left: 3px solid #e6a817; background: #fffcf0; padding: 8px 12px; margin: 3px 0; border-radius: 0 4px 4px 0; font-size: 0.88em; }
    .step-obs { border-left: 3px solid #4caf50; background: #f0fff0; padding: 8px 12px; margin: 3px 0; border-radius: 0 4px 4px 0; font-size: 0.88em; }
    .log-line { font-family: monospace; font-size: 0.82em; color: #555; margin: 1px 0; }
</style>
""", unsafe_allow_html=True)


# --- Helpers d'affichage ---

def show_reasoning(messages: list):
    for step in messages:
        if step["type"] == "think":
            content = step["content"]
            if isinstance(content, list):
                content = " ".join(item.get("text", "") for item in content if isinstance(item, dict) and "text" in item)
            st.markdown(f'<div class="step-think"><b>Think</b> — {str(content)[:300]}</div>', unsafe_allow_html=True)
        elif step["type"] == "act":
            args_short = ", ".join(f"{k}={str(v)[:50]}" for k, v in step.get("args", {}).items())
            st.markdown(f'<div class="step-act"><b>Act</b> — <code>{step.get("tool", "?")}({args_short})</code></div>', unsafe_allow_html=True)
        elif step["type"] == "observe":
            st.markdown(f'<div class="step-obs"><b>Observe</b> — <code>{step.get("tool", "?")}</code> &rarr; {str(step.get("content", ""))[:150]}</div>', unsafe_allow_html=True)


def show_metrics(scan_result):
    c1, c2, c3, c4 = st.columns(4)
    auth = sum(1 for ep in scan_result.endpoints if ep.auth_required)
    c1.metric("Ports", len(scan_result.open_ports))
    c2.metric("Endpoints", len(scan_result.endpoints))
    c3.metric("Proteges", auth)
    c4.metric("Formulaires", len(scan_result.forms))


def show_severity_chart(attack_plan):
    counts = {}
    for v in attack_plan.vectors:
        sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        counts[sev] = counts.get(sev, 0) + 1
    if not counts:
        return
    colors = {"CRITICAL": "#d32f2f", "HIGH": "#f57c00", "MEDIUM": "#fbc02d", "LOW": "#388e3c"}
    fig = go.Figure(data=[go.Pie(
        labels=list(counts.keys()), values=list(counts.values()), hole=0.5,
        marker_colors=[colors.get(k, "#757575") for k in counts.keys()],
    )])
    fig.update_layout(title="Severites", height=300, margin=dict(t=40, b=20, l=20, r=20))
    st.plotly_chart(fig, use_container_width=True)


def show_attack_chart(attack_result):
    failed = attack_result.total_attempts - attack_result.successful_attacks
    fig = go.Figure(data=[go.Bar(
        x=["Reussies", "Echouees"], y=[attack_result.successful_attacks, failed],
        marker_color=["#388e3c", "#d32f2f"],
    )])
    fig.update_layout(title="Attaques", height=300, margin=dict(t=40, b=20, l=20, r=20))
    st.plotly_chart(fig, use_container_width=True)


def capture_stdout(func, *args, **kwargs):
    """Execute une fonction et capture sa sortie stdout ligne par ligne."""
    output = StringIO()
    result = None

    def run():
        nonlocal result
        with redirect_stdout(output):
            result = func(*args, **kwargs)

    thread = threading.Thread(target=run)
    thread.start()

    return thread, output, lambda: result


# --- Sidebar ---
with st.sidebar:
    st.title("RedSimulator")
    st.caption("Pipeline de securite automatise par IA")
    st.divider()
    use_fixtures = st.toggle("Mode fixtures", value=True)
    st.caption("Donnees simulees au lieu de vrais scans")
    st.divider()
    show_agent = st.toggle("Raisonnement agent", value=True)
    show_endpoints = st.toggle("Details endpoints", value=False)
    st.divider()
    st.markdown("**Pipeline** : Scanner → Expert → Generator → Executor → Reporter")


# --- Main ---
st.title("RedSimulator")
st.caption("INF8790 UQAM — PoC academique")

col1, col2 = st.columns([3, 1])
with col1:
    target_url = st.text_input("URL cible", value="http://localhost:3000")
with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    run_button = st.button("Lancer", type="primary", use_container_width=True)


if run_button:
    agent_messages = []
    fixtures_dir = Path(__file__).parent.parent / "data" / "fixtures"

    # =========================================================
    # ETAPE 1 — SCANNER
    # =========================================================
    step1_status = st.status("[1/5] Scanner — Reconnaissance...", expanded=True)
    log_area = step1_status.empty()

    try:
        from src.scanner.agent import ReconAgent

        if use_fixtures:
            scan_result = ReconAgent.from_fixture()
            step1_status.write(f"Fixture chargee — {len(scan_result.endpoints)} endpoints")
        else:
            # Lancer le scan et capturer les logs en live
            agent = ReconAgent(target_url)

            # Capturer stdout pour affichage live
            log_capture = StringIO()
            import sys
            old_stdout = sys.stdout
            sys.stdout = log_capture

            scan_result = agent.run()

            sys.stdout = old_stdout
            agent_messages = agent.agent_messages

            # Afficher les logs captures
            logs = log_capture.getvalue()
            if logs:
                log_lines = logs.strip().split("\n")
                # Montrer les dernieres lignes significatives
                display_lines = [l for l in log_lines if l.strip() and not l.startswith("  [*]")]
                step1_status.code("\n".join(display_lines[-20:]), language="text")

            mode = "Agent ReAct" if agent_messages else "Fallback"
            step1_status.write(f"{mode} — {len(scan_result.endpoints)} endpoints, {len(scan_result.forms)} formulaires")

        step1_status.update(label="[1/5] Scanner — Termine", state="complete", expanded=False)
    except Exception as e:
        step1_status.update(label="[1/5] Scanner — Erreur", state="error")
        st.error(str(e))
        st.exception(e)
        st.stop()

    # Raisonnement de l'agent
    if agent_messages and show_agent:
        with st.expander("Raisonnement de l'agent ReAct", expanded=True):
            show_reasoning(agent_messages)

    # Resultats du scan
    st.subheader("Resultats du scan")
    show_metrics(scan_result)

    if scan_result.technologies:
        st.markdown("**Technologies :** " + ", ".join(scan_result.technologies))

    col_h, col_f = st.columns(2)
    with col_h:
        with st.expander("Headers de securite"):
            missing = scan_result.headers.missing_security_headers
            if missing:
                for h in missing:
                    st.markdown(f"- **{h}** — manquant")
            if scan_result.headers.server_info_leaked:
                st.markdown("- **Server/X-Powered-By** — expose")
            if not missing and not scan_result.headers.server_info_leaked:
                st.success("Tous les headers sont presents.")

    with col_f:
        if scan_result.forms:
            with st.expander(f"Formulaires ({len(scan_result.forms)})"):
                for form in scan_result.forms:
                    field_names = ", ".join(f.name for f in form.fields)
                    st.markdown(f"- **{form.endpoint}** : {field_names}")

    if show_endpoints:
        with st.expander(f"Endpoints ({len(scan_result.endpoints)})"):
            data = [{"Chemin": ep.path, "Methode": ep.method, "Status": ep.status_code, "Auth": "Oui" if ep.auth_required else "Non"} for ep in scan_result.endpoints]
            st.dataframe(data, use_container_width=True, hide_index=True)

    st.divider()

    # =========================================================
    # ETAPE 2 — EXPERT
    # =========================================================
    step2_status = st.status("[2/5] Systeme Expert — Analyse...", expanded=True)
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

        step2_status.write(f"{len(attack_plan.vectors)} vecteurs identifies")
        step2_status.update(label="[2/5] Systeme Expert — Termine", state="complete", expanded=False)
    except Exception as e:
        step2_status.update(label="[2/5] Systeme Expert — Erreur", state="error")
        st.error(str(e))
        st.stop()

    # =========================================================
    # ETAPE 3 — GENERATOR
    # =========================================================
    step3_status = st.status("[3/5] Generator — Payloads...", expanded=True)
    try:
        from src.models import PayloadResult
        if use_fixtures:
            data = json.loads((fixtures_dir / "payload_result.json").read_text())
            payload_result = PayloadResult.model_validate(data)
        else:
            payload_result = PayloadResult(payloads=[])

        step3_status.write(f"{len(payload_result.payloads)} payloads")
        step3_status.update(label="[3/5] Generator — Termine", state="complete", expanded=False)
    except Exception as e:
        step3_status.update(label="[3/5] Generator — Erreur", state="error")
        st.error(str(e))
        st.stop()

    # =========================================================
    # ETAPE 4 — EXECUTOR
    # =========================================================
    step4_status = st.status("[4/5] Executor — Attaques...", expanded=True)
    try:
        from src.models import AttackResult
        if use_fixtures:
            data = json.loads((fixtures_dir / "attack_result.json").read_text())
            attack_result = AttackResult.model_validate(data)
        else:
            from src.executor.runner import AttackExecutor
            executor = AttackExecutor(target_url)
            attack_result = executor.execute_all(attack_plan, payload_result)

        step4_status.write(f"{attack_result.successful_attacks}/{attack_result.total_attempts} reussies")
        step4_status.update(label="[4/5] Executor — Termine", state="complete", expanded=False)
    except Exception as e:
        step4_status.update(label="[4/5] Executor — Erreur", state="error")
        st.error(str(e))
        st.stop()

    # =========================================================
    # ETAPE 5 — REPORTER
    # =========================================================
    step5_status = st.status("[5/5] Reporter — Rapport...", expanded=True)
    try:
        from src.reporter.report_generator import generate_report
        report = generate_report(scan_result, attack_plan, attack_result)
        step5_status.write(f"Rapport genere ({len(report)} car.)")
        step5_status.update(label="[5/5] Reporter — Termine", state="complete", expanded=False)
    except Exception as e:
        step5_status.update(label="[5/5] Reporter — Erreur", state="error")
        st.error(str(e))
        st.stop()

    st.divider()

    # =========================================================
    # RESULTATS
    # =========================================================
    st.header("Analyse des vulnerabilites")

    col_c1, col_c2 = st.columns(2)
    with col_c1:
        show_severity_chart(attack_plan)
    with col_c2:
        show_attack_chart(attack_result)

    # Vecteurs
    st.subheader("Vecteurs d'attaque")
    for v in attack_plan.vectors:
        sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        atype = v.attack_type.value if hasattr(v.attack_type, "value") else str(v.attack_type)
        with st.expander(f"{v.id} — {atype} ({sev}) — {v.target_endpoint}"):
            st.markdown(f"**OWASP :** {v.owasp_ref}")
            if v.rationale:
                st.markdown("**Analyse :**")
                for r in v.rationale:
                    st.markdown(f"- {r}")
            if v.base_payloads:
                st.markdown("**Payloads de base :**")
                st.code("\n".join(v.base_payloads))

    st.divider()

    # Rapport
    st.header("Rapport de securite")
    st.markdown(report)

else:
    st.info("Cliquez sur **Lancer** pour demarrer le pipeline.")

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("""
        **Utilisation**
        1. `docker-compose up -d`
        2. Desactivez le mode fixtures
        3. Cliquez sur Lancer
        """)
    with col_b:
        st.markdown("""
        **Modes**
        - **Fixtures** — Donnees simulees
        - **Live** — Vrai scan contre Juice Shop
        - **Agent ReAct** — Claude raisonne (cle API)
        """)

    reports_dir = Path(__file__).parent.parent / "data" / "reports"
    report_path = reports_dir / "report.md"
    if report_path.exists():
        with st.expander("Dernier rapport"):
            st.markdown(report_path.read_text())
