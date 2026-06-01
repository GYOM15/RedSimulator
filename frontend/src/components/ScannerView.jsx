/**
 * ScannerView.jsx — Vue de la phase Scanner
 */

import ScrollBox from "./ScrollBox";

export default function ScannerView({ logs, agentSteps, endpoints, ports, techs, headers, forms, stats }) {
  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        {[
          { label: "Endpoints", value: endpoints.length, color: "#e53935" },
          { label: "Ports", value: ports.length, color: "#42a5f5" },
          { label: "Formulaires", value: forms.length, color: "#ab47bc" },
          { label: "Headers manquants", value: headers.length, color: "#ffa726" },
        ].map((m, i) => (
          <div key={i} style={{ background: "#1a1a2e", borderRadius: 8, padding: "12px 20px", flex: 1, textAlign: "center" }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: m.color }}>{m.value}</div>
            <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>{m.label}</div>
          </div>
        ))}
      </div>

      {techs.length > 0 && (
        <div style={{ marginBottom: 12, fontSize: 12, color: "#888" }}>
          Technologies : {techs.map((t, i) => <span key={i} style={{ background: "#1a1a2e", padding: "2px 8px", borderRadius: 4, marginRight: 6, color: "#ccc" }}>{t}</span>)}
        </div>
      )}

      <ScrollBox deps={[logs.length, agentSteps.length, endpoints.length, forms.length]}>
        {/* Agent reasoning */}
        {agentSteps.map((step, i) => (
          <div key={`a-${i}`} style={{
            marginBottom: 4, padding: "8px 12px", borderRadius: 6, animation: "fadeIn 0.3s",
            background: step.type === "think" ? "#1a1a2e" : step.type === "act" ? "#1a1520" : "#111a10",
            borderLeft: step.type === "think" ? "2px solid #42a5f5" : step.type === "act" ? "2px solid #ab47bc" : "2px solid #ffa726",
          }}>
            {step.type === "think" && <div style={{ fontSize: 12, color: "#90caf9" }}>💭 <b>Think</b> — {String(typeof step.content === "string" ? step.content : JSON.stringify(step.content)).slice(0, 250)}</div>}
            {step.type === "act" && <div style={{ fontSize: 12, color: "#ce93d8" }}>⚡ <b>Act</b> — <code style={{ background: "#2a1a35", padding: "1px 6px", borderRadius: 3, fontSize: 11 }}>{step.tool}</code></div>}
            {step.type === "observe" && <div style={{ fontSize: 12, color: "#ffcc80" }}>👁 <b>Observe</b> — {String(step.content || "").slice(0, 120)}</div>}
            {step.type === "log" && <div style={{ fontSize: 11, color: "#888", fontFamily: "monospace", padding: "2px 0" }}>▸ {step.content}</div>}
          </div>
        ))}

        {/* Endpoints */}
        {endpoints.map((ep, i) => (
          <div key={`e-${i}`} style={{ display: "flex", gap: 8, alignItems: "center", padding: "4px 12px", marginBottom: 2, borderRadius: 4, background: "#0d1a0d", animation: "fadeIn 0.2s" }}>
            <span style={{ background: "#1b5e20", padding: "1px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700 }}>{ep.method}</span>
            <code style={{ fontSize: 11, color: "#a5d6a7", flex: 1 }}>{ep.path}</code>
            <span style={{ fontSize: 10, color: "#666" }}>{ep.status_code}</span>
            {ep.auth_required && <span style={{ fontSize: 9, background: "#b71c1c", padding: "1px 5px", borderRadius: 3 }}>AUTH</span>}
          </div>
        ))}

        {/* Headers manquants */}
        {headers.map((h, i) => (
          <div key={`h-${i}`} style={{ fontSize: 11, color: "#ffa726", padding: "2px 12px", animation: "fadeIn 0.2s" }}>Header manquant : <b>{h}</b></div>
        ))}

        {/* Formulaires */}
        {forms.map((f, i) => (
          <div key={`f-${i}`} style={{ padding: "6px 12px", marginBottom: 4, borderRadius: 4, background: "#1a1020", borderLeft: "2px solid #ab47bc", animation: "fadeIn 0.3s" }}>
            <div style={{ fontSize: 12, color: "#ce93d8", fontWeight: 600 }}>{f.endpoint} ({f.source})</div>
            <div style={{ fontSize: 11, color: "#888" }}>{(f.fields || []).map(fl => fl.name || fl).join(", ")}</div>
          </div>
        ))}
      </ScrollBox>
    </div>
  );
}
