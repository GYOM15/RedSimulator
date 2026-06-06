/**
 * Sidebar.jsx — Navigation du pipeline
 *
 * - Les phases completees sont cliquables pour revenir en arriere
 * - La phase active a un indicateur pulsant
 * - Les phases completees ont un check vert
 * - La navigation ne perturbe pas le pipeline en cours
 */

import { STEPS } from "../styles/theme";

export default function Sidebar({ currentPhase, completedPhases, activeView, onSelectView, pipelineDone, onReset, onOpenChat, onOpenProxy, proxyRunning, onOpenSettings, llmConfig, pentestRunning, pentestDone, pentestFindings }) {
  return (
    <div style={{
      width: 220, borderRight: "1px solid #1e1e2e", padding: "16px 12px",
      flexShrink: 0, display: "flex", flexDirection: "column",
      overflowY: "auto",
    }}>
      <div style={{
        fontSize: 11, fontWeight: 700, letterSpacing: 2, color: "#555",
        marginBottom: 16, textTransform: "uppercase", paddingLeft: 4,
      }}>
        Pipeline
      </div>

      {/* Pentest mode indicator */}
      {(pentestRunning || pentestDone) && (
        <div
          onClick={() => onSelectView("pentest")}
          style={{
            display: "flex", alignItems: "center", gap: 10,
            padding: "10px 12px", marginBottom: 12,
            borderRadius: 8, cursor: "pointer",
            background: activeView === "pentest" ? "#1a1a2e" : "transparent",
            borderLeft: activeView === "pentest"
              ? "3px solid #ab47bc"
              : pentestDone
                ? "3px solid #2e7d32"
                : "3px solid #ab47bc",
            border: `1px solid ${pentestRunning ? "#ab47bc40" : pentestDone ? "#2e7d3240" : "#1a1a2e"}`,
          }}
        >
          <div style={{
            width: 8, height: 8, borderRadius: "50%",
            background: pentestDone ? "#2e7d32" : "#ab47bc",
            animation: pentestRunning ? "pulse 1.5s infinite" : "none",
          }} />
          <div style={{ flex: 1 }}>
            <div style={{
              fontSize: 13, fontWeight: 700,
              color: pentestRunning ? "#ab47bc" : pentestDone ? "#aaa" : "#555",
            }}>
              Pentester
            </div>
            <div style={{ fontSize: 10, color: "#444" }}>Agent autonome</div>
          </div>
          {pentestDone && <span style={{ color: "#2e7d32", fontSize: 14 }}>&#10003;</span>}
          {pentestRunning && (
            <span style={{ fontSize: 9, color: "#ab47bc", fontWeight: 700, animation: "pulse 1.5s infinite" }}>
              &#9679;
            </span>
          )}
          {pentestFindings && pentestFindings.length > 0 && (
            <span style={{
              fontSize: 10, fontWeight: 800, color: "#e53935",
              background: "#e5393520", padding: "1px 6px", borderRadius: 4,
            }}>
              {pentestFindings.length}
            </span>
          )}
        </div>
      )}

      {/* Pipeline steps separator */}
      {(pentestRunning || pentestDone) && (
        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 2, color: "#333", marginBottom: 8, paddingLeft: 4 }}>
          PIPELINE
        </div>
      )}

      {STEPS.map((s) => {
        const isRunning = s.id === currentPhase && !pipelineDone;
        const done = completedPhases.includes(s.id);
        const viewing = s.id === activeView;
        const clickable = done || isRunning;

        return (
          <div
            key={s.id}
            onClick={() => clickable && onSelectView(s.id)}
            style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "10px 12px", marginBottom: 6,
              borderRadius: 8, transition: "all 0.2s",
              cursor: clickable ? "pointer" : "default",
              background: viewing ? "#1a1a2e" : "transparent",
              borderLeft: viewing
                ? "3px solid #e53935"
                : done
                  ? "3px solid #2e7d32"
                  : isRunning
                    ? "3px solid #ffa726"
                    : "3px solid transparent",
              opacity: clickable ? 1 : 0.35,
            }}
          >
            {/* Phase status dot */}
            <div style={{
              width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
              background: done ? "#2e7d32" : isRunning ? "#ffa726" : "#333",
              animation: isRunning ? "pulse 1.5s infinite" : "none",
            }} />

            {/* Phase label */}
            <div style={{ flex: 1 }}>
              <div style={{
                fontSize: 13, fontWeight: 600, textAlign: "left",
                color: viewing ? "#fff" : done ? "#aaa" : isRunning ? "#ffa726" : "#555",
              }}>
                {s.name}
              </div>
              <div style={{ fontSize: 10, color: "#444", textAlign: "left" }}>{s.tech}</div>
            </div>

            {/* Checkmark for completed */}
            {done && <span style={{ color: "#2e7d32", fontSize: 14, flexShrink: 0 }}>&#10003;</span>}

            {/* Pulsing indicator for running */}
            {isRunning && !done && (
              <span style={{
                fontSize: 9, color: "#ffa726", fontWeight: 700,
                animation: "pulse 1.5s infinite", flexShrink: 0,
              }}>
                &#9679;
              </span>
            )}
          </div>
        );
      })}

      <div style={{ flex: 1 }} />

      {/* Proxy button */}
      <button onClick={onOpenProxy} style={{
        width: "100%", background: activeView === "proxy" ? "#1a1a2e" : "transparent",
        border: `1px solid ${proxyRunning ? "#42a5f5" : "#333"}`, borderRadius: 8,
        padding: "10px", color: proxyRunning ? "#42a5f5" : "#888", fontSize: 12, fontWeight: 700,
        cursor: "pointer", marginBottom: 8, display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
        fontFamily: "inherit",
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
          <button onClick={() => onSelectView("summary")} style={{
            width: "100%", background: activeView === "summary" ? "#1a1a2e" : "transparent",
            border: "1px solid #2e7d32", borderRadius: 8,
            padding: "10px", color: "#2e7d32", fontSize: 12, fontWeight: 700,
            cursor: "pointer", marginBottom: 8, fontFamily: "inherit",
          }}>
            Recapitulatif
          </button>
          <button onClick={onOpenChat} style={{
            width: "100%", background: "#e53935", border: "none", borderRadius: 8,
            padding: "10px", color: "#fff", fontSize: 12, fontWeight: 700,
            cursor: "pointer", marginBottom: 8, fontFamily: "inherit",
          }}>
            Chat RAG
          </button>
        </>
      )}

      {/* LLM Settings button */}
      <button onClick={onOpenSettings} style={{
        width: "100%", background: "transparent",
        border: "1px solid #333", borderRadius: 8,
        padding: "10px", color: "#888", fontSize: 12, fontWeight: 600,
        cursor: "pointer", marginBottom: 8, fontFamily: "inherit",
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

      <button onClick={onReset} style={{
        width: "100%", background: "#1a1a2e", border: "1px solid #333", borderRadius: 8,
        padding: "8px", color: "#888", fontSize: 11, cursor: "pointer", fontFamily: "inherit",
      }}>
        Recommencer
      </button>
    </div>
  );
}
