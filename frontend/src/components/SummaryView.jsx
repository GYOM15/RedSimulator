/**
 * SummaryView.jsx — Recapitulatif avec graphiques
 */

import { SEV } from "../styles/theme";
import { DonutChart, BarChart } from "./Charts";

export default function SummaryView({ scanStats, vectors, payloadCount, attackStats }) {
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
