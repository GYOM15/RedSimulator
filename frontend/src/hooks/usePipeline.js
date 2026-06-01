/**
 * usePipeline.js — Hook personnalise encapsulant les 18+ useState
 * et la logique de connexion SSE du pipeline RedSimulator.
 */

import { useState, useRef, useCallback } from "react";
import { API } from "../styles/theme";

export default function usePipeline() {
  const [phase, setPhase] = useState("idle");
  const [completedPhases, setCompletedPhases] = useState([]);
  const [activeView, setActiveView] = useState("scanning");
  const [showChat, setShowChat] = useState(false);
  const [target, setTarget] = useState("http://localhost:3000");
  const [useFixtures, setUseFixtures] = useState(true);
  const [elapsed, setElapsed] = useState(0);
  const [pipelineDone, setPipelineDone] = useState(false);
  const timerRef = useRef(null);

  // Data per phase
  const [scanLogs, setScanLogs] = useState([]);
  const [agentSteps, setAgentSteps] = useState([]);
  const [scanStats, setScanStats] = useState({ endpoints: 0, ports: 0, forms: 0, missingHeaders: 0 });
  const [endpoints, setEndpoints] = useState([]);
  const [ports, setPorts] = useState([]);
  const [techs, setTechs] = useState([]);
  const [missingHeaders, setMissingHeaders] = useState([]);
  const [forms, setForms] = useState([]);
  const [rules, setRules] = useState([]);
  const [vectors, setVectors] = useState([]);
  const [payloads, setPayloads] = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [attackStats, setAttackStats] = useState({});
  const [reportText, setReportText] = useState("");

  const reset = () => {
    clearInterval(timerRef.current);
    setPhase("idle"); setCompletedPhases([]); setActiveView("scanning"); setShowChat(false);
    setElapsed(0); setPipelineDone(false);
    setScanLogs([]); setAgentSteps([]); setScanStats({ endpoints: 0, ports: 0, forms: 0, missingHeaders: 0 });
    setEndpoints([]); setPorts([]); setTechs([]); setMissingHeaders([]); setForms([]);
    setRules([]); setVectors([]); setPayloads([]); setAttacks([]); setAttackStats({}); setReportText("");
  };

  const run = useCallback(() => {
    reset();
    setPhase("scanning"); setActiveView("scanning");
    timerRef.current = setInterval(() => setElapsed(e => e + 1), 1000);

    const url = useFixtures ? `${API}/scan/fixtures` : `${API}/scan/stream?target=${encodeURIComponent(target)}`;
    const src = new EventSource(url);

    src.addEventListener("phase", (e) => {
      const d = JSON.parse(e.data);
      setPhase(d.phase);
      setActiveView(d.phase);
    });

    src.addEventListener("phase_done", (e) => {
      const d = JSON.parse(e.data);
      setCompletedPhases(prev => [...new Set([...prev, d.phase])]);
    });

    src.addEventListener("scan_log", (e) => {
      const text = JSON.parse(e.data).text;
      setScanLogs(prev => [...prev, text]);
      setAgentSteps(prev => [...prev, { type: "log", content: text }]);
    });
    src.addEventListener("agent_step", (e) => { setAgentSteps(prev => [...prev, JSON.parse(e.data)]); });
    src.addEventListener("scan_result", (e) => {
      const d = JSON.parse(e.data);
      setScanStats({ endpoints: d.endpoints, ports: d.ports, forms: d.forms, missingHeaders: d.missing_headers?.length || 0 });
    });
    src.addEventListener("endpoint", (e) => { setEndpoints(prev => [...prev, JSON.parse(e.data)]); });
    src.addEventListener("port", (e) => { setPorts(prev => [...prev, JSON.parse(e.data)]); });
    src.addEventListener("technology", (e) => { setTechs(prev => [...prev, JSON.parse(e.data).name]); });
    src.addEventListener("missing_header", (e) => { setMissingHeaders(prev => [...prev, JSON.parse(e.data).name]); });
    src.addEventListener("form", (e) => { setForms(prev => [...prev, JSON.parse(e.data)]); });
    src.addEventListener("rule_fired", (e) => { setRules(prev => [...prev, JSON.parse(e.data).rule]); });
    src.addEventListener("vector", (e) => { setVectors(prev => [...prev, JSON.parse(e.data)]); });
    src.addEventListener("payload", (e) => { setPayloads(prev => [...prev, JSON.parse(e.data)]); });
    src.addEventListener("attack", (e) => { setAttacks(prev => [...prev, JSON.parse(e.data)]); });
    src.addEventListener("executor_result", (e) => { setAttackStats(JSON.parse(e.data)); });
    src.addEventListener("report_chunk", (e) => { setReportText(prev => prev + JSON.parse(e.data).text); });

    src.addEventListener("pipeline_done", () => {
      setPipelineDone(true); setActiveView("summary"); clearInterval(timerRef.current); src.close();
    });
    src.addEventListener("error", () => { src.close(); });
  }, [target, useFixtures]);

  return {
    // Pipeline state
    phase,
    completedPhases,
    activeView,
    setActiveView,
    showChat,
    setShowChat,
    target,
    setTarget,
    useFixtures,
    setUseFixtures,
    elapsed,
    pipelineDone,

    // Data
    scanLogs,
    agentSteps,
    scanStats,
    endpoints,
    ports,
    techs,
    missingHeaders,
    forms,
    rules,
    vectors,
    payloads,
    attacks,
    attackStats,
    reportText,

    // Actions
    reset,
    run,
  };
}
