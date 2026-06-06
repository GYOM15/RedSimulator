/**
 * usePipeline.js — Hook personnalise encapsulant les 18+ useState
 * et la logique de connexion SSE du pipeline RedSimulator.
 */

import { useState, useRef, useCallback, useEffect } from "react";
import { API } from "../styles/theme";

export default function usePipeline() {
  const [phase, setPhase] = useState("idle");
  const [completedPhases, setCompletedPhases] = useState([]);
  const [activeView, setActiveView] = useState("scanning");
  const [userNavigated, setUserNavigated] = useState(false);
  const userNavigatedRef = useRef(false);
  const [showChat, setShowChat] = useState(false);
  const [target, setTarget] = useState("http://localhost:3000");
  const [useFixtures, setUseFixtures] = useState(false);
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

  // Passive scan findings
  const [passiveFindings, setPassiveFindings] = useState([]);
  // Validation confidence results
  const [validationResults, setValidationResults] = useState([]);

  // LLM config state
  const [llmConfig, setLlmConfig] = useState(null);

  // Proxy state
  const [proxyRunning, setProxyRunning] = useState(false);
  const [proxyAvailable, setProxyAvailable] = useState(null); // null = unknown
  const [proxyStatus, setProxyStatus] = useState(null);
  const [proxyFlows, setProxyFlows] = useState([]);
  const proxyEsRef = useRef(null);

  // Wrap setActiveView: when called by user (from sidebar), mark userNavigated
  const setActiveViewUser = useCallback((view) => {
    setActiveView(view);
    setUserNavigated(true);
    userNavigatedRef.current = true;
  }, []);

  const reset = () => {
    clearInterval(timerRef.current);
    setPhase("idle"); setCompletedPhases([]); setActiveView("scanning"); setShowChat(false);
    setUserNavigated(false); userNavigatedRef.current = false;
    setElapsed(0); setPipelineDone(false);
    setScanLogs([]); setAgentSteps([]); setScanStats({ endpoints: 0, ports: 0, forms: 0, missingHeaders: 0 });
    setEndpoints([]); setPorts([]); setTechs([]); setMissingHeaders([]); setForms([]);
    setRules([]); setVectors([]); setPayloads([]); setAttacks([]); setAttackStats({}); setReportText("");
    setPassiveFindings([]); setValidationResults([]);
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
      // Only auto-switch view if user hasn't manually navigated
      if (!userNavigatedRef.current) {
        setActiveView(d.phase);
      }
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

    // Passive scan events
    src.addEventListener("passive_finding", (e) => { setPassiveFindings(prev => [...prev, JSON.parse(e.data)]); });
    src.addEventListener("passive_complete", (e) => { setPassiveFindings(JSON.parse(e.data).findings || JSON.parse(e.data)); });

    // Validation confidence events
    src.addEventListener("validation_result", (e) => { setValidationResults(prev => [...prev, JSON.parse(e.data)]); });
    src.addEventListener("validation_complete", (e) => { setValidationResults(JSON.parse(e.data).results || JSON.parse(e.data)); });

    src.addEventListener("report_chunk", (e) => { setReportText(prev => prev + JSON.parse(e.data).text); });

    src.addEventListener("pipeline_done", () => {
      setPipelineDone(true);
      // Auto-switch to summary, and reset userNavigated on completion
      setActiveView("summary");
      setUserNavigated(false);
      userNavigatedRef.current = false;
      clearInterval(timerRef.current);
      src.close();
    });
    src.addEventListener("error", () => {
      src.close();
      clearInterval(timerRef.current);
      setPhase("idle");
      setScanLogs(prev => [...prev, "Erreur: connexion au serveur perdue. Verifiez que le backend est demarre sur le port 8080."]);
    });
  }, [target, useFixtures]);

  // ---------------------------------------------------------------------------
  // LLM config actions
  // ---------------------------------------------------------------------------

  const fetchLlmConfig = useCallback(async () => {
    try {
      const resp = await fetch(`${API}/settings/llm`);
      if (resp.ok) {
        const data = await resp.json();
        setLlmConfig(data);
      }
    } catch (e) {
      console.error("Failed to fetch LLM config:", e);
    }
  }, []);

  const saveLlmConfig = useCallback(async (config) => {
    const resp = await fetch(`${API}/settings/llm`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    if (!resp.ok) {
      const errData = await resp.json().catch(() => ({}));
      throw new Error(errData.detail || "Failed to save LLM configuration");
    }
    const data = await resp.json();
    setLlmConfig((prev) => ({ ...prev, ...data }));
  }, []);

  const clearLlmConfig = useCallback(async () => {
    const resp = await fetch(`${API}/settings/llm`, { method: "DELETE" });
    if (!resp.ok) throw new Error("Failed to clear LLM configuration");
    await fetchLlmConfig();
  }, [fetchLlmConfig]);

  // ---------------------------------------------------------------------------
  // Proxy actions
  // ---------------------------------------------------------------------------

  const fetchProxyStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API}/proxy/status`);
      if (res.ok) {
        const data = await res.json();
        setProxyStatus(data);
        setProxyRunning(data.running);
        setProxyAvailable(data.available);
      }
    } catch {
      // API not reachable — proxy status unknown
    }
  }, []);

  const startProxy = useCallback(async () => {
    try {
      const res = await fetch(`${API}/proxy/start`, { method: "POST" });
      if (res.ok) {
        setProxyRunning(true);
        await fetchProxyStatus();
        // Start SSE stream for live flows
        if (proxyEsRef.current) proxyEsRef.current.close();
        const es = new EventSource(`${API}/proxy/flows/stream`);
        es.addEventListener("flow", (e) => {
          const flow = JSON.parse(e.data);
          setProxyFlows((prev) => [flow, ...prev]);
        });
        es.addEventListener("error", () => { /* keep-alive timeouts are normal */ });
        proxyEsRef.current = es;
      }
    } catch (err) {
      console.error("Failed to start proxy:", err);
    }
  }, [fetchProxyStatus]);

  const stopProxy = useCallback(async () => {
    try {
      const res = await fetch(`${API}/proxy/stop`, { method: "POST" });
      if (res.ok) {
        setProxyRunning(false);
        if (proxyEsRef.current) {
          proxyEsRef.current.close();
          proxyEsRef.current = null;
        }
        await fetchProxyStatus();
      }
    } catch (err) {
      console.error("Failed to stop proxy:", err);
    }
  }, [fetchProxyStatus]);

  const feedProxy = useCallback(async () => {
    try {
      const res = await fetch(`${API}/proxy/feed`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        return data;
      }
    } catch (err) {
      console.error("Failed to feed proxy:", err);
    }
    return null;
  }, []);

  const replayFlow = useCallback(async (flowId) => {
    try {
      const res = await fetch(`${API}/proxy/flows/${flowId}/replay`, { method: "POST" });
      if (res.ok) {
        const newFlow = await res.json();
        setProxyFlows((prev) => [newFlow, ...prev]);
        return newFlow;
      }
    } catch (err) {
      console.error("Failed to replay flow:", err);
    }
    return null;
  }, []);

  const clearProxyFlows = useCallback(async () => {
    try {
      const res = await fetch(`${API}/proxy/flows`, { method: "DELETE" });
      if (res.ok) {
        setProxyFlows([]);
        await fetchProxyStatus();
      }
    } catch (err) {
      console.error("Failed to clear proxy flows:", err);
    }
  }, [fetchProxyStatus]);

  // Fetch proxy status and LLM config on mount
  useEffect(() => {
    fetchProxyStatus();
    fetchLlmConfig();
  }, [fetchProxyStatus, fetchLlmConfig]);

  return {
    // Pipeline state
    phase,
    completedPhases,
    activeView,
    setActiveView: setActiveViewUser,
    userNavigated,
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
    passiveFindings,
    validationResults,

    // Actions
    reset,
    run,

    // LLM config
    llmConfig,
    saveLlmConfig,
    clearLlmConfig,

    // Proxy
    proxyRunning,
    proxyAvailable,
    proxyStatus,
    proxyFlows,
    startProxy,
    stopProxy,
    feedProxy,
    replayFlow,
    clearProxyFlows,
  };
}
