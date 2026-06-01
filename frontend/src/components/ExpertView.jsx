/**
 * ExpertView.jsx — Vue du systeme expert
 */

import ScrollBox from "./ScrollBox";
import { SEV } from "../styles/theme";

export default function ExpertView({ rules, vectors }) {
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
              <div style={{ marginTop: 4 }}>{v.rationale.map((r, j) => <div key={j} style={{ fontSize: 11, color: "#777", paddingLeft: 8 }}>{"▸"} {r}</div>)}</div>
            )}
          </div>
        ))}
      </ScrollBox>
    </div>
  );
}
