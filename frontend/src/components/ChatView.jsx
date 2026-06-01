/**
 * ChatView.jsx — Chatbot RAG
 */

import { useState, useRef, useEffect, useCallback } from "react";
import { Md } from "./Markdown";
import { API } from "../styles/theme";

export default function ChatView() {
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
