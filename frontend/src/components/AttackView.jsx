/**
 * AttackView.jsx — Vue de l'executeur d'attaques
 */

import ScrollBox from "./ScrollBox";

export default function AttackView({ attacks, stats }) {
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
            <span style={{ fontSize: 12, width: 18, color: a.success ? "#4caf50" : "#ef5350" }}>{a.success ? "✓" : "✗"}</span>
            <span style={{ fontSize: 10, background: a.success ? "#1b5e20" : "#b71c1c", padding: "1px 6px", borderRadius: 3, fontWeight: 700, textTransform: "uppercase" }}>{a.vector_id || a.attack_type || ""}</span>
            <code style={{ fontSize: 11, color: a.success ? "#a5d6a7" : "#ef9a9a", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.payload}</code>
            <span style={{ fontSize: 10, color: "#555" }}>{a.target_endpoint || a.endpoint || ""}</span>
          </div>
        ))}
      </ScrollBox>
    </div>
  );
}
