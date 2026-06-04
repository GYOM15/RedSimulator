/**
 * Sidebar.jsx — Navigation du pipeline
 */

import { STEPS } from "../styles/theme";

export default function Sidebar({ currentPhase, completedPhases, activeView, onSelectView, pipelineDone, onReset, onOpenChat, onOpenProxy, proxyRunning, onOpenSettings, llmConfig }) {
  return (
    <div style={{ width: 220, borderRight: "1px solid #1e1e2e", padding: 16, flexShrink: 0, display: "flex", flexDirection: "column" }}>
      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 2, color: "#555", marginBottom: 16, textTransform: "uppercase" }}>Pipeline</div>
      {STEPS.map((s) => {
        const active = s.id === currentPhase;
        const done = completedPhases.includes(s.id);
        const viewing = s.id === activeView;
        const clickable = done || active;
        return (
          <div key={s.id} onClick={() => clickable && onSelectView(s.id)} style={{
            display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", marginBottom: 4,
            borderRadius: 8, transition: "all 0.3s", cursor: clickable ? "pointer" : "default",
            background: viewing ? "#1a1a2e" : "transparent",
            borderLeft: viewing ? "3px solid #e53935" : done ? "3px solid #2e7d32" : active ? "3px solid #ffa726" : "3px solid transparent",
            opacity: clickable ? 1 : 0.35,
          }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: done ? "#2e7d32" : active ? "#ffa726" : "#333", animation: active && !done ? "pulse 1.5s infinite" : "none" }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: viewing ? "#fff" : done ? "#aaa" : "#555" }}>{s.name}</div>
              <div style={{ fontSize: 10, color: "#444" }}>{s.tech}</div>
            </div>
            {done && <span style={{ color: "#2e7d32", fontSize: 14 }}>{"✓"}</span>}
          </div>
        );
      })}

      <div style={{ flex: 1 }} />

      {/* Proxy button — always visible */}
      <button onClick={onOpenProxy} style={{
        width: "100%", background: activeView === "proxy" ? "#1a1a2e" : "transparent",
        border: `1px solid ${proxyRunning ? "#42a5f5" : "#333"}`, borderRadius: 8,
        padding: "10px", color: proxyRunning ? "#42a5f5" : "#888", fontSize: 12, fontWeight: 700,
        cursor: "pointer", marginBottom: 8, display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
      }}>
        <div style={{
          width: 6, height: 6, borderRadius: "50%",
          background: proxyRunning ? "#42a5f5" : "#555",
          animation: proxyRunning ? "pulse 1.5s infinite" : "none",
        }} />
        Proxy
      </button>

      {pipelineDone && (
        <>
          <button onClick={() => onSelectView("summary")} style={{ width: "100%", background: "#1a1a2e", border: "1px solid #2e7d32", borderRadius: 8, padding: "10px", color: "#2e7d32", fontSize: 12, fontWeight: 700, cursor: "pointer", marginBottom: 8 }}>
            Recapitulatif
          </button>
          <button onClick={onOpenChat} style={{ width: "100%", background: "#e53935", border: "none", borderRadius: 8, padding: "10px", color: "#fff", fontSize: 12, fontWeight: 700, cursor: "pointer", marginBottom: 8 }}>
            Chat RAG
          </button>
        </>
      )}
      {/* LLM Settings button */}
      <button onClick={onOpenSettings} style={{
        width: "100%", background: "transparent",
        border: "1px solid #333", borderRadius: 8,
        padding: "10px", color: "#888", fontSize: 12, fontWeight: 600,
        cursor: "pointer", marginBottom: 8,
        display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
      }}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
        {llmConfig?.provider
          ? <span>{llmConfig.provider === "anthropic" ? "Claude" : llmConfig.provider === "openai" ? "OpenAI" : "Ollama"}{llmConfig.api_key_set ? " ✓" : ""}</span>
          : "LLM Config"
        }
      </button>

      <button onClick={onReset} style={{ width: "100%", background: "#1a1a2e", border: "1px solid #333", borderRadius: 8, padding: "8px", color: "#888", fontSize: 11, cursor: "pointer" }}>
        Recommencer
      </button>
    </div>
  );
}
