/**
 * VAEView.jsx — Vue du generateur VAE
 */

import ScrollBox from "./ScrollBox";

export default function VAEView({ payloads }) {
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
