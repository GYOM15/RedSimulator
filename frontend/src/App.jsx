/**
 * RedSimulator — Frontend React
 *
 * Interface temps reel connectee au backend FastAPI via SSE.
 * Chaque etape du pipeline s'affiche en live avec le detail
 * des pensees, actions et observations de l'agent.
 */

import { useState } from "react";
import usePipeline from "./hooks/usePipeline";
import Sidebar from "./components/Sidebar";
import ScannerView from "./components/ScannerView";
import ExpertView from "./components/ExpertView";
import GeneratorView from "./components/VAEView";
import AttackView from "./components/AttackView";
import PassiveView from "./components/PassiveView";
import ValidatorView from "./components/ValidatorView";
import ReportView from "./components/ReportView";
import ChatView from "./components/ChatView";
import SummaryView from "./components/SummaryView";
import ProxyView from "./components/ProxyView";
import PentestView from "./components/PentestView";
import SettingsPanel from "./components/SettingsPanel";

export default function App() {
  const pipeline = usePipeline();

  const {
    phase, completedPhases, activeView, setActiveView,
    userNavigated,
    showChat, setShowChat, target, setTarget,
    useFixtures, setUseFixtures, elapsed, pipelineDone,
    scanLogs, agentSteps, scanStats, endpoints, ports,
    techs, missingHeaders, forms, rules, vectors,
    payloads, attacks, attackStats, reportText,
    passiveFindings, validationResults,
    reset, run,
    // LLM config
    llmConfig, saveLlmConfig, clearLlmConfig,
    // Proxy
    proxyRunning, proxyAvailable, proxyStatus, proxyFlows,
    startProxy, stopProxy, feedProxy, replayFlow, clearProxyFlows,
    // Pentester agent
    pentestMode, setPentestMode,
    pentestRunning, pentestPhase, pentestReasoning,
    pentestActions, pentestFindings, pentestResult,
    pentestDone, runPentest, resetPentest,
  } = pipeline;

  const [showProxy, setShowProxy] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  const viewContent = () => {
    if (showProxy) return <ProxyView proxyStatus={proxyStatus} flows={proxyFlows} onStart={startProxy} onStop={stopProxy} onReplay={replayFlow} onFeed={feedProxy} onClear={clearProxyFlows} proxyAvailable={proxyAvailable} />;
    if (showChat) return <ChatView />;
    if (activeView === "pentest") return <PentestView reasoning={pentestReasoning} actions={pentestActions} findings={pentestFindings} result={pentestResult} pentestPhase={pentestPhase} pentestRunning={pentestRunning} pentestDone={pentestDone} />;
    if (pipelineDone && activeView === "summary") return <SummaryView scanStats={scanStats} vectors={vectors} payloadCount={payloads.length} attackStats={attackStats} />;
    switch (activeView) {
      case "scanning": return <ScannerView logs={scanLogs} agentSteps={agentSteps} endpoints={endpoints} ports={ports} techs={techs} headers={missingHeaders} forms={forms} stats={scanStats} />;
      case "passive": return <PassiveView findings={passiveFindings} />;
      case "expert": return <ExpertView rules={rules} vectors={vectors} />;
      case "generator": return <GeneratorView payloads={payloads} />;
      case "attacking": return <AttackView attacks={attacks} stats={attackStats} />;
      case "validation": return <ValidatorView validationResults={validationResults} attackResults={attacks} />;
      case "reporting": return <ReportView text={reportText} />;
      default: return null;
    }
  };

  const viewTitle = () => {
    if (showProxy) return "Proxy MITM — Interception";
    if (showChat) return "Chatbot RAG";
    const labels = {
      scanning: "Scanner — Reconnaissance",
      passive: "Scan Passif — Decouvertes",
      expert: "Systeme Expert — Analyse",
      generator: "Generateur — Mutations",
      attacking: "Executeur — Attaques",
      validation: "Validation — Confiance",
      reporting: "Rapporteur — Generation",
      summary: "Recapitulatif",
      pentest: "Pentester Autonome — Agent IA",
    };
    return labels[activeView] || "";
  };

  return (
    <div style={{
      background: "#09090f", color: "#fff",
      height: "100vh", display: "flex", flexDirection: "column",
      fontFamily: "'SF Mono', 'Fira Code', Consolas, monospace",
      overflow: "hidden",
    }}>
      <style>{`
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
        @keyframes glow { 0%, 100% { box-shadow: 0 0 20px #e5393520; } 50% { box-shadow: 0 0 40px #e5393540; } }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
      `}</style>

      {/* Header — fixed, does not scroll with content */}
      <div style={{
        borderBottom: "1px solid #1a1a2e", padding: "12px 24px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 10, height: 10, borderRadius: "50%",
            background: pentestRunning ? "#ab47bc" : (phase !== "idle" && !pipelineDone) ? "#e53935" : (pipelineDone || pentestDone) ? "#2e7d32" : "#555",
            animation: (pentestRunning || (phase !== "idle" && !pipelineDone)) ? "pulse 1.5s infinite" : "none",
          }} />
          <span style={{ fontSize: 18, fontWeight: 800, letterSpacing: 2, color: "#e53935" }}>RED</span>
          <span style={{ fontSize: 18, fontWeight: 300, letterSpacing: 2 }}>SIMULATOR</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, fontSize: 12, color: "#666" }}>
          {phase !== "idle" && <span>{Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2, "0")}</span>}
          {phase !== "idle" && <span>{target}</span>}
          {/* Viewing indicator when user navigated away from running phase */}
          {userNavigated && !pipelineDone && phase !== "idle" && activeView !== phase && (
            <span style={{ fontSize: 10, color: "#ffa726", padding: "2px 8px", background: "#1a1a2e", borderRadius: 4 }}>
              Visualisation: {activeView}
            </span>
          )}
          <button onClick={() => setShowSettings(true)} style={{
            background: "none", border: "1px solid #333", borderRadius: 6,
            padding: "4px 10px", color: "#888", fontSize: 11, cursor: "pointer",
            display: "flex", alignItems: "center", gap: 6,
          }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
            LLM
            {llmConfig?.api_key_set && <span style={{ color: "#2e7d32" }}>&#x2713;</span>}
          </button>
        </div>
      </div>

      {/* Idle */}
      {phase === "idle" && !pentestRunning && !pentestDone && (
        <div style={{
          display: "flex", flexDirection: "column", alignItems: "center",
          justifyContent: "center", flex: 1, gap: 24,
        }}>
          <div style={{ fontSize: 56, fontWeight: 900, letterSpacing: 6, color: "#e53935", animation: "glow 3s infinite" }}>
            RED<span style={{ color: "#fff", fontWeight: 200 }}>SIMULATOR</span>
          </div>
          <div style={{ fontSize: 13, color: "#555", letterSpacing: 3, textTransform: "uppercase" }}>Test de securite automatise par IA</div>
          <div style={{ marginTop: 20, display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <input value={target} onChange={e => setTarget(e.target.value)}
                style={{ background: "#111", border: "1px solid #333", borderRadius: 8, padding: "12px 20px", color: "#fff", fontSize: 14, minWidth: 300, outline: "none", fontFamily: "inherit" }} />
              <button onClick={run} style={{ background: "linear-gradient(135deg, #e53935, #c62828)", border: "none", borderRadius: 8, padding: "12px 28px", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer", letterSpacing: 1, fontFamily: "inherit" }}>
                PIPELINE
              </button>
              <button onClick={runPentest} style={{
                background: "linear-gradient(135deg, #ab47bc, #7b1fa2)",
                border: "none", borderRadius: 8, padding: "12px 28px",
                color: "#fff", fontSize: 14, fontWeight: 700,
                cursor: "pointer", letterSpacing: 1, fontFamily: "inherit",
              }}>
                PENTEST
              </button>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
              <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "#666", cursor: "pointer" }}>
                <input type="checkbox" checked={useFixtures} onChange={e => setUseFixtures(e.target.checked)} style={{ accentColor: "#e53935" }} />
                Mode fixtures (donnees simulees)
              </label>
              <span style={{ fontSize: 11, color: "#444" }}>
                PIPELINE = scan + exploit sequentiel | PENTEST = agent autonome
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Running (pipeline or pentest) */}
      {(phase !== "idle" || pentestRunning || pentestDone) && (
        <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
          <Sidebar
            currentPhase={phase}
            completedPhases={completedPhases}
            activeView={showProxy ? "proxy" : showChat ? "chat" : activeView}
            onSelectView={(id) => { setShowProxy(false); setShowChat(false); setActiveView(id); }}
            pipelineDone={pipelineDone}
            onReset={() => { reset(); resetPentest(); }}
            onOpenChat={() => { setShowProxy(false); setShowChat(true); }}
            onOpenProxy={() => { setShowChat(false); setShowProxy(true); }}
            proxyRunning={proxyRunning}
            onOpenSettings={() => setShowSettings(true)}
            llmConfig={llmConfig}
            pentestRunning={pentestRunning}
            pentestDone={pentestDone}
            pentestFindings={pentestFindings}
          />

          <div style={{
            flex: 1, padding: 24, minHeight: 0,
            display: "flex", flexDirection: "column", overflow: "hidden",
          }}>
            {/* View title bar */}
            <div style={{
              fontSize: 18, fontWeight: 700, marginBottom: 16,
              display: "flex", alignItems: "center", gap: 8,
              flexShrink: 0,
            }}>
              {viewTitle()}
              {((!pipelineDone && phase !== "idle") || pentestRunning) && (
                <span style={{ animation: "pulse 1.5s infinite", fontSize: 10, color: pentestRunning ? "#ab47bc" : "#e53935", marginLeft: 8 }}>EN COURS</span>
              )}
              {(pipelineDone || pentestDone) && !showChat && (
                <span style={{ fontSize: 10, color: "#2e7d32", marginLeft: 8 }}>TERMINE</span>
              )}
            </div>

            {/* View content — fills remaining space */}
            <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
              {viewContent()}
            </div>
          </div>
        </div>
      )}

      {/* LLM Settings Modal */}
      <SettingsPanel
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
        llmConfig={llmConfig}
        onSave={saveLlmConfig}
        onClear={clearLlmConfig}
      />
    </div>
  );
}
