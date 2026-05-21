/**
 * RedSimulator — Frontend React
 *
 * Interface temps reel connectee au backend FastAPI via SSE.
 * Chaque etape du pipeline s'affiche en live avec le detail
 * des pensees, actions et observations de l'agent.
 */

import { useState, useEffect, useRef, useCallback } from "react";

const API = "/api";

const STEPS = [
  { id: "scanning", name: "Scanner", tech: "Agent ReAct" },
  { id: "expert", name: "Analyseur", tech: "Systeme expert" },
  { id: "vae", name: "Generateur", tech: "VAE" },
  { id: "attacking", name: "Executeur", tech: "Attaques" },
  { id: "reporting", name: "Rapporteur", tech: "LLM" },
];

const SEV = { CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#ca8a04", LOW: "#16a34a" };

/* ── Markdown renderer ── */
function InlineText({ text }) {
  // Parse bold, inline code, et texte normal
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((p, j) => {
    if (p.startsWith("**")) return <b key={j} style={{ color: "#fff" }}>{p.slice(2, -2)}</b>;
    if (p.startsWith("`")) return <code key={j} style={{ background: "#1a1a2e", padding: "1px 5px", borderRadius: 3, fontSize: 11, color: "#ef9a9a" }}>{p.slice(1, -1)}</code>;
    return <span key={j}>{p}</span>;
  });
}

function MdTable({ rows }) {
  // rows = lignes brutes "| col1 | col2 |"
  const parsed = rows.map(r => r.split("|").filter(c => c.trim()).map(c => c.trim()));
  if (parsed.length < 2) return null;
  const header = parsed[0];
  // Ignorer la ligne de separateur (|---|---|)
  const body = parsed.filter((_, i) => i > 0 && !/^[-:\s]+$/.test(rows[i]));
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", marginBottom: 12, fontSize: 11 }}>
      <thead>
        <tr>{header.map((h, i) => <th key={i} style={{ textAlign: "left", padding: "6px 10px", borderBottom: "1px solid #333", color: "#aaa", fontWeight: 600 }}>{h}</th>)}</tr>
      </thead>
      <tbody>
        {body.map((row, i) => (
          <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : "#0d0d14" }}>
            {row.map((cell, j) => {
              const sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].find(s => cell.includes(s));
              return <td key={j} style={{ padding: "5px 10px", borderBottom: "1px solid #1a1a2e", color: sev ? SEV[sev] : "#ccc" }}><InlineText text={cell} /></td>;
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Md({ text }) {
  if (!text) return null;
  const lines = text.split("\n");
  const elements = [];
  let i = 0;
  let inCodeBlock = false;
  let codeLines = [];

  while (i < lines.length) {
    const line = lines[i];

    // Code block
    if (line.startsWith("```")) {
      if (inCodeBlock) {
        elements.push(<pre key={`code-${i}`} style={{ background: "#111", border: "1px solid #222", borderRadius: 6, padding: "10px 14px", fontSize: 11, color: "#a5d6a7", overflowX: "auto", margin: "6px 0" }}>{codeLines.join("\n")}</pre>);
        codeLines = [];
        inCodeBlock = false;
      } else {
        inCodeBlock = true;
      }
      i++; continue;
    }
    if (inCodeBlock) { codeLines.push(line); i++; continue; }

    // Table (groupe les lignes | ... |)
    if (line.startsWith("|")) {
      const tableRows = [];
      while (i < lines.length && lines[i].startsWith("|")) { tableRows.push(lines[i]); i++; }
      elements.push(<MdTable key={`tbl-${i}`} rows={tableRows} />);
      continue;
    }

    // Headings
    if (line.startsWith("# ")) { elements.push(<div key={i} style={{ fontSize: 20, fontWeight: 700, color: "#fff", margin: "14px 0 8px", borderBottom: "1px solid #333", paddingBottom: 6 }}>{line.slice(2)}</div>); i++; continue; }
    if (line.startsWith("## ")) { elements.push(<div key={i} style={{ fontSize: 16, fontWeight: 700, color: "#e53935", margin: "14px 0 6px" }}>{line.slice(3)}</div>); i++; continue; }
    if (line.startsWith("### ")) { elements.push(<div key={i} style={{ fontSize: 14, fontWeight: 700, color: "#ffa726", margin: "10px 0 4px" }}>{line.slice(4)}</div>); i++; continue; }

    // List
    if (line.startsWith("- ")) { elements.push(<div key={i} style={{ paddingLeft: 16, marginBottom: 2, fontSize: 12 }}>{"\u25b8"} <InlineText text={line.slice(2)} /></div>); i++; continue; }

    // Numbered list
    if (line.match(/^\d+\./)) { elements.push(<div key={i} style={{ paddingLeft: 16, marginBottom: 2, fontSize: 12, color: "#aaa" }}><InlineText text={line} /></div>); i++; continue; }

    // Horizontal rule
    if (line.trim() === "---") { elements.push(<hr key={i} style={{ border: "none", borderTop: "1px solid #222", margin: "10px 0" }} />); i++; continue; }

    // Empty
    if (line.trim() === "") { elements.push(<div key={i} style={{ height: 6 }} />); i++; continue; }

    // Normal text with inline formatting
    elements.push(<div key={i} style={{ fontSize: 12, marginBottom: 3, color: "#ccc" }}><InlineText text={line} /></div>);
    i++;
  }

  return <div style={{ fontSize: 13, lineHeight: 1.7 }}>{elements}</div>;
}

/* ── Sidebar ── */
function Sidebar({ currentPhase, completedPhases, activeView, onSelectView, pipelineDone, onReset, onOpenChat }) {
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
            {done && <span style={{ color: "#2e7d32", fontSize: 14 }}>{"\u2713"}</span>}
          </div>
        );
      })}

      <div style={{ flex: 1 }} />

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
      <button onClick={onReset} style={{ width: "100%", background: "#1a1a2e", border: "1px solid #333", borderRadius: 8, padding: "8px", color: "#888", fontSize: 11, cursor: "pointer" }}>
        Recommencer
      </button>
    </div>
  );
}

/* ── Auto-scroll container ── */
function ScrollBox({ children, deps }) {
  const ref = useRef(null);
  useEffect(() => { ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" }); }, [deps]);
  return <div ref={ref} style={{ maxHeight: 420, overflowY: "auto", paddingRight: 4 }}>{children}</div>;
}

/* ── Scanner view ── */
function ScannerView({ logs, agentSteps, endpoints, ports, techs, headers, forms, stats }) {
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

/* ── Expert view ── */
function ExpertView({ rules, vectors }) {
  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        <div style={{ background: "#1a1a2e", borderRadius: 8, padding: "12px 20px", flex: 1, textAlign: "center" }}>
          <div style={{ fontSize: 28, fontWeight: 800, color: "#e53935" }}>{vectors.length}</div>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>Vecteurs</div>
        </div>
        <div style={{ background: "#1a1a2e", borderRadius: 8, padding: "12px 20px", flex: 1, textAlign: "center" }}>
          <div style={{ fontSize: 28, fontWeight: 800, color: "#ffa726" }}>{rules.length}</div>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>Regles activees</div>
        </div>
        <div style={{ background: "#1a1a2e", borderRadius: 8, padding: "12px 20px", flex: 1, textAlign: "center" }}>
          <div style={{ fontSize: 28, fontWeight: 800, color: "#ab47bc" }}>{vectors.filter(v => v.severity === "CRITICAL").length}</div>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>Critiques</div>
        </div>
      </div>
      <ScrollBox deps={[rules.length, vectors.length]}>
        {rules.map((r, i) => (
          <div key={`r-${i}`} style={{ fontSize: 11, color: "#66bb6a", padding: "4px 12px", borderLeft: "2px solid #2e7d32", marginBottom: 3, animation: "fadeIn 0.3s" }}>
            Regle activee : <b>{r}</b>
          </div>
        ))}
        {vectors.map((v, i) => (
          <div key={`v-${i}`} style={{
            padding: "10px 12px", marginBottom: 6, borderRadius: 6, animation: "fadeIn 0.4s",
            background: `${SEV[v.severity] || "#555"}11`, borderLeft: `3px solid ${SEV[v.severity] || "#555"}`,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <span style={{ fontWeight: 700, fontSize: 13, color: SEV[v.severity] }}>{v.id} — {v.attack_type}</span>
              <span style={{ marginLeft: "auto", fontSize: 10, background: `${SEV[v.severity]}22`, color: SEV[v.severity], padding: "2px 8px", borderRadius: 10, fontWeight: 600 }}>{v.severity}</span>
            </div>
            <div style={{ fontSize: 11, color: "#999", fontFamily: "monospace" }}>Cible : {v.target_endpoint}</div>
            <div style={{ fontSize: 11, color: "#888" }}>OWASP : {v.owasp_ref}</div>
            {v.rationale && v.rationale.length > 0 && (
              <div style={{ marginTop: 4 }}>{v.rationale.map((r, j) => <div key={j} style={{ fontSize: 11, color: "#777", paddingLeft: 8 }}>{"\u25b8"} {r}</div>)}</div>
            )}
          </div>
        ))}
      </ScrollBox>
    </div>
  );
}

/* ── VAE view ── */
function VAEView({ payloads }) {
  return (
    <div>
      <div style={{ background: "#1a1a2e", borderRadius: 8, padding: "12px 20px", marginBottom: 16, textAlign: "center" }}>
        <div style={{ fontSize: 28, fontWeight: 800, color: "#ab47bc" }}>{payloads.length}</div>
        <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>Payloads generes</div>
      </div>
      <ScrollBox deps={[payloads.length]}>
        {payloads.map((p, i) => (
          <div key={i} style={{ marginBottom: 6, padding: "8px 12px", background: "#0d1a0d", border: "1px solid #1b5e20", borderRadius: 6, animation: "fadeIn 0.3s" }}>
            <span style={{ fontSize: 10, background: "#e53935", padding: "2px 8px", borderRadius: 10, fontWeight: 700, textTransform: "uppercase", marginRight: 8 }}>{p.attack_type || "payload"}</span>
            <code style={{ fontSize: 11, color: "#a5d6a7" }}>{p.payload || p.original || JSON.stringify(p)}</code>
          </div>
        ))}
      </ScrollBox>
    </div>
  );
}

/* ── Attack view ── */
function AttackView({ attacks, stats }) {
  const s = attacks.filter(a => a.success).length;
  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        <div style={{ background: "#1a1a2e", borderRadius: 8, padding: "12px 20px", flex: 1, textAlign: "center" }}>
          <div style={{ fontSize: 28, fontWeight: 800, color: "#2e7d32" }}>{stats.successful ?? s}</div>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>Reussies</div>
        </div>
        <div style={{ background: "#1a1a2e", borderRadius: 8, padding: "12px 20px", flex: 1, textAlign: "center" }}>
          <div style={{ fontSize: 28, fontWeight: 800, color: "#e53935" }}>{(stats.total ?? attacks.length) - (stats.successful ?? s)}</div>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>Bloquees</div>
        </div>
      </div>
      <ScrollBox deps={[attacks.length]}>
        {attacks.map((a, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 8, padding: "7px 12px", marginBottom: 4, borderRadius: 6,
            background: a.success ? "#0d1a0d" : "#1a0d0d", borderLeft: `3px solid ${a.success ? "#2e7d32" : "#b71c1c"}`,
            animation: "fadeIn 0.3s",
          }}>
            <span style={{ fontSize: 12, width: 18, color: a.success ? "#4caf50" : "#ef5350" }}>{a.success ? "\u2713" : "\u2717"}</span>
            <span style={{ fontSize: 10, background: a.success ? "#1b5e20" : "#b71c1c", padding: "1px 6px", borderRadius: 3, fontWeight: 700, textTransform: "uppercase" }}>{a.vector_id || a.attack_type || ""}</span>
            <code style={{ fontSize: 11, color: a.success ? "#a5d6a7" : "#ef9a9a", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.payload}</code>
            <span style={{ fontSize: 10, color: "#555" }}>{a.target_endpoint || a.endpoint || ""}</span>
          </div>
        ))}
      </ScrollBox>
    </div>
  );
}

/* ── Report view ── */
function ReportView({ text }) {
  const ref = useRef(null);
  useEffect(() => { ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" }); }, [text]);
  return (
    <div ref={ref} style={{ maxHeight: 440, overflowY: "auto", padding: "0 8px" }}>
      <Md text={text} />
      {text && <span style={{ animation: "blink 1s infinite", color: "#e53935" }}>{"\u2588"}</span>}
    </div>
  );
}

/* ── Chat view ── */
function ChatView() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const ref = useRef(null);
  useEffect(() => { ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" }); }, [messages]);

  const suggestions = ["Quelles vulnerabilites critiques ?", "Comment corriger le SQLi ?", "Quels endpoints sont risques ?"];

  const send = useCallback(async (text) => {
    const q = text || input;
    if (!q.trim()) return;
    setMessages(prev => [...prev, { role: "user", content: q }]);
    setInput(""); setLoading(true);
    try {
      const r = await fetch(`${API}/chat`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question: q }) });
      const d = await r.json();
      setMessages(prev => [...prev, { role: "assistant", content: d.answer }]);
    } catch { setMessages(prev => [...prev, { role: "assistant", content: "Erreur de connexion." }]); }
    setLoading(false);
  }, [input]);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: 440 }}>
      <div ref={ref} style={{ flex: 1, overflowY: "auto", marginBottom: 12 }}>
        {messages.length === 0 && (
          <div style={{ padding: 20, textAlign: "center" }}>
            <div style={{ fontSize: 14, color: "#888", marginBottom: 16 }}>Posez une question sur le rapport</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {suggestions.map((s, i) => (
                <button key={i} onClick={() => send(s)} style={{ background: "#1a1a2e", border: "1px solid #333", borderRadius: 8, padding: "10px 14px", color: "#aaa", fontSize: 12, cursor: "pointer", textAlign: "left" }}>{s}</button>
              ))}
            </div>
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} style={{ display: "flex", justifyContent: m.role === "user" ? "flex-end" : "flex-start", marginBottom: 8 }}>
            <div style={{ maxWidth: "80%", padding: "10px 14px", borderRadius: 12, background: m.role === "user" ? "#e53935" : "#1a1a2e" }}>
              {m.role === "user" ? <span style={{ fontSize: 12, color: "#fff" }}>{m.content}</span> : <Md text={m.content} />}
            </div>
          </div>
        ))}
        {loading && <div style={{ color: "#888", fontSize: 12, padding: 8 }}>Reflexion...</div>}
      </div>
      <div style={{ display: "flex", gap: 8 }}>
        <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && send()}
          placeholder="Posez une question..." disabled={loading}
          style={{ flex: 1, background: "#111", border: "1px solid #333", borderRadius: 8, padding: "10px 14px", color: "#fff", fontSize: 13, outline: "none" }} />
        <button onClick={() => send()} disabled={loading || !input.trim()}
          style={{ background: "#e53935", border: "none", borderRadius: 8, padding: "10px 18px", color: "#fff", fontWeight: 700, cursor: "pointer", opacity: loading || !input.trim() ? 0.5 : 1 }}>
          Envoyer
        </button>
      </div>
    </div>
  );
}

/* ── Bar chart CSS ── */
function BarChart({ data, height = 160 }) {
  const max = Math.max(...data.map(d => d.value), 1);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 8, height, padding: "0 4px" }}>
      {data.map((d, i) => (
        <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: d.color || "#ccc" }}>{d.value}</div>
          <div style={{
            width: "100%", borderRadius: "4px 4px 0 0",
            height: `${(d.value / max) * (height - 40)}px`,
            background: d.color || "#555",
            transition: "height 0.5s ease-out",
            minHeight: 2,
          }} />
          <div style={{ fontSize: 9, color: "#888", textAlign: "center" }}>{d.label}</div>
        </div>
      ))}
    </div>
  );
}

/* ── Donut chart CSS ── */
function DonutChart({ data, size = 140 }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  let cumulative = 0;
  const segments = data.map(d => {
    const start = cumulative;
    cumulative += (d.value / total) * 360;
    return { ...d, start, end: cumulative };
  });
  const gradientParts = segments.map(s => `${s.color} ${s.start}deg ${s.end}deg`).join(", ");
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <div style={{
        width: size, height: size, borderRadius: "50%",
        background: `conic-gradient(${gradientParts})`,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        <div style={{ width: size * 0.6, height: size * 0.6, borderRadius: "50%", background: "#09090f", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <span style={{ fontSize: 20, fontWeight: 800, color: "#fff" }}>{total}</span>
        </div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {data.map((d, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color }} />
            <span style={{ color: "#aaa" }}>{d.label}</span>
            <span style={{ color: d.color, fontWeight: 700 }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Summary view ── */
function SummaryView({ scanStats, vectors, payloadCount, attackStats }) {
  // Severity counts
  const sevCounts = {};
  vectors.forEach(v => { sevCounts[v.severity] = (sevCounts[v.severity] || 0) + 1; });
  const sevData = Object.entries(sevCounts).map(([k, v]) => ({ label: k, value: v, color: SEV[k] || "#555" }));

  const successful = attackStats.successful || 0;
  const failed = (attackStats.total || 0) - successful;

  return (
    <div>
      <div style={{ fontSize: 16, fontWeight: 700, color: "#2e7d32", marginBottom: 20 }}>Pipeline termine</div>

      {/* Metriques */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 12, marginBottom: 24 }}>
        {[
          { label: "Endpoints", value: scanStats.endpoints, color: "#e53935" },
          { label: "Vecteurs", value: vectors.length, color: "#ffa726" },
          { label: "Payloads", value: payloadCount, color: "#ab47bc" },
          { label: "Attaques reussies", value: successful, color: "#2e7d32" },
        ].map((m, i) => (
          <div key={i} style={{ background: "#1a1a2e", borderRadius: 8, padding: 16, textAlign: "center" }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: m.color }}>{m.value}</div>
            <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>{m.label}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 24 }}>
        <div style={{ background: "#0f0f17", borderRadius: 8, padding: 16, border: "1px solid #1e1e2e" }}>
          <div style={{ fontSize: 12, color: "#888", marginBottom: 12, fontWeight: 600 }}>Severite des vulnerabilites</div>
          {sevData.length > 0 ? <DonutChart data={sevData} /> : <div style={{ color: "#555", fontSize: 12 }}>Aucun vecteur</div>}
        </div>
        <div style={{ background: "#0f0f17", borderRadius: 8, padding: 16, border: "1px solid #1e1e2e" }}>
          <div style={{ fontSize: 12, color: "#888", marginBottom: 12, fontWeight: 600 }}>Resultats des attaques</div>
          <BarChart data={[
            { label: "Reussies", value: successful, color: "#2e7d32" },
            { label: "Echouees", value: failed, color: "#b71c1c" },
            { label: "Total", value: attackStats.total || 0, color: "#42a5f5" },
          ]} />
        </div>
      </div>

      {/* Scanner details */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div style={{ background: "#0f0f17", borderRadius: 8, padding: 16, border: "1px solid #1e1e2e" }}>
          <div style={{ fontSize: 12, color: "#888", marginBottom: 8, fontWeight: 600 }}>Scanner</div>
          <BarChart height={100} data={[
            { label: "Ports", value: scanStats.ports, color: "#42a5f5" },
            { label: "Endpoints", value: scanStats.endpoints, color: "#e53935" },
            { label: "Formulaires", value: scanStats.forms, color: "#ab47bc" },
            { label: "Headers", value: scanStats.missingHeaders, color: "#ffa726" },
          ]} />
        </div>
        <div style={{ background: "#0f0f17", borderRadius: 8, padding: 16, border: "1px solid #1e1e2e" }}>
          <div style={{ fontSize: 12, color: "#888", marginBottom: 8, fontWeight: 600 }}>Vecteurs par type</div>
          <BarChart height={100} data={
            Object.entries(vectors.reduce((acc, v) => { acc[v.attack_type] = (acc[v.attack_type] || 0) + 1; return acc; }, {}))
              .map(([k, v]) => ({ label: k, value: v, color: "#e53935" }))
          } />
        </div>
      </div>

      <div style={{ marginTop: 16, fontSize: 12, color: "#666" }}>
        Naviguez entre les etapes via le menu, ou ouvrez le chat RAG.
      </div>
    </div>
  );
}

/* ── Main ── */
export default function App() {
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

  const viewContent = () => {
    if (showChat) return <ChatView />;
    if (pipelineDone && activeView === "summary") return <SummaryView scanStats={scanStats} vectors={vectors} payloadCount={payloads.length} attackStats={attackStats} />;
    switch (activeView) {
      case "scanning": return <ScannerView logs={scanLogs} agentSteps={agentSteps} endpoints={endpoints} ports={ports} techs={techs} headers={missingHeaders} forms={forms} stats={scanStats} />;
      case "expert": return <ExpertView rules={rules} vectors={vectors} />;
      case "vae": return <VAEView payloads={payloads} />;
      case "attacking": return <AttackView attacks={attacks} stats={attackStats} />;
      case "reporting": return <ReportView text={reportText} />;
      default: return null;
    }
  };

  const viewTitle = () => {
    if (showChat) return "Chatbot RAG";
    const labels = { scanning: "Scanner — Reconnaissance", expert: "Systeme Expert — Analyse", vae: "Generateur VAE — Mutations", attacking: "Executeur — Attaques", reporting: "Rapporteur — Generation", summary: "Recapitulatif" };
    return labels[activeView] || "";
  };

  return (
    <div style={{ background: "#09090f", color: "#fff", minHeight: "100vh", fontFamily: "'SF Mono', 'Fira Code', Consolas, monospace" }}>
      <style>{`
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
        @keyframes glow { 0%, 100% { box-shadow: 0 0 20px #e5393520; } 50% { box-shadow: 0 0 40px #e5393540; } }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
      `}</style>

      {/* Header */}
      <div style={{ borderBottom: "1px solid #1a1a2e", padding: "12px 24px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: phase !== "idle" && !pipelineDone ? "#e53935" : pipelineDone ? "#2e7d32" : "#555", animation: phase !== "idle" && !pipelineDone ? "pulse 1.5s infinite" : "none" }} />
          <span style={{ fontSize: 18, fontWeight: 800, letterSpacing: 2, color: "#e53935" }}>RED</span>
          <span style={{ fontSize: 18, fontWeight: 300, letterSpacing: 2 }}>SIMULATOR</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, fontSize: 12, color: "#666" }}>
          {phase !== "idle" && <span>{Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2, "0")}</span>}
          {phase !== "idle" && <span>{target}</span>}
        </div>
      </div>

      {/* Idle */}
      {phase === "idle" && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "calc(100vh - 50px)", gap: 24 }}>
          <div style={{ fontSize: 56, fontWeight: 900, letterSpacing: 6, color: "#e53935", animation: "glow 3s infinite" }}>
            RED<span style={{ color: "#fff", fontWeight: 200 }}>SIMULATOR</span>
          </div>
          <div style={{ fontSize: 13, color: "#555", letterSpacing: 3, textTransform: "uppercase" }}>Test de securite automatise par IA</div>
          <div style={{ marginTop: 20, display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <input value={target} onChange={e => setTarget(e.target.value)}
                style={{ background: "#111", border: "1px solid #333", borderRadius: 8, padding: "12px 20px", color: "#fff", fontSize: 14, minWidth: 300, outline: "none" }} />
              <button onClick={run} style={{ background: "linear-gradient(135deg, #e53935, #c62828)", border: "none", borderRadius: 8, padding: "12px 28px", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer", letterSpacing: 1 }}>
                LANCER
              </button>
            </div>
            <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "#666", cursor: "pointer" }}>
              <input type="checkbox" checked={useFixtures} onChange={e => setUseFixtures(e.target.checked)} style={{ accentColor: "#e53935" }} />
              Mode fixtures (donnees simulees)
            </label>
          </div>
        </div>
      )}

      {/* Running */}
      {phase !== "idle" && (
        <div style={{ display: "flex", height: "calc(100vh - 50px)" }}>
          <Sidebar currentPhase={phase} completedPhases={completedPhases} activeView={showChat ? "chat" : activeView}
            onSelectView={(id) => { setShowChat(false); setActiveView(id); }}
            pipelineDone={pipelineDone} onReset={reset}
            onOpenChat={() => setShowChat(true)} />

          <div style={{ flex: 1, padding: 24, overflow: "hidden" }}>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
              {viewTitle()}
              {!pipelineDone && phase !== "idle" && <span style={{ animation: "pulse 1.5s infinite", fontSize: 10, color: "#e53935", marginLeft: 8 }}>EN COURS</span>}
              {pipelineDone && !showChat && <span style={{ fontSize: 10, color: "#2e7d32", marginLeft: 8 }}>TERMINE</span>}
            </div>
            {viewContent()}
          </div>
        </div>
      )}
    </div>
  );
}
