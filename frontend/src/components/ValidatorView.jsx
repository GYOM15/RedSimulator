/**
 * ValidatorView.jsx — Vue de la validation de confiance
 */

import { useState } from "react";
import ScrollBox from "./ScrollBox";
import { CONFIDENCE_COLORS, BG_CARD } from "../styles/theme";

const CONFIDENCE_ORDER = ["confirmed", "likely", "possible", "unlikely", "false_positive"];
const CONFIDENCE_LABELS = {
  confirmed: "Confirme",
  likely: "Probable",
  possible: "Possible",
  unlikely: "Improbable",
  false_positive: "Faux positif",
};

const CONFIDENCE_THRESHOLD = 0.4;

export default function ValidatorView({ validationResults, attackResults }) {
  const [expandedIdx, setExpandedIdx] = useState(null);

  const results = validationResults || [];
  const attacks = attackResults || [];

  if (results.length === 0 && attacks.length === 0) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 300, color: "#555", fontSize: 14 }}>
        Aucun resultat de validation pour le moment.
      </div>
    );
  }

  // Build lookup for attack payloads
  const attackMap = {};
  for (const a of attacks) {
    if (a.vector_id) attackMap[a.vector_id] = a;
  }

  // Count by confidence label
  const distribution = {};
  for (const label of CONFIDENCE_ORDER) distribution[label] = 0;
  for (const r of results) {
    const label = r.confidence?.label || "possible";
    if (distribution[label] !== undefined) distribution[label]++;
    else distribution[label] = (distribution[label] || 0) + 1;
  }

  const total = results.length || 1;

  return (
    <div>
      {/* Stat cards */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        {CONFIDENCE_ORDER.map((label) => (
          <div key={label} style={{ background: BG_CARD, borderRadius: 8, padding: "12px 20px", flex: 1, textAlign: "center" }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: CONFIDENCE_COLORS[label] }}>{distribution[label]}</div>
            <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>{CONFIDENCE_LABELS[label]}</div>
          </div>
        ))}
      </div>

      {/* Confidence distribution bar */}
      <div style={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", marginBottom: 16 }}>
        {CONFIDENCE_ORDER.map((label) => {
          const count = distribution[label];
          if (count === 0) return null;
          return (
            <div key={label} style={{ flex: count, background: CONFIDENCE_COLORS[label], transition: "flex 0.5s" }}
              title={`${CONFIDENCE_LABELS[label]}: ${count}`} />
          );
        })}
      </div>

      {/* Validation results table */}
      <ScrollBox deps={[results.length, expandedIdx]}>
        {/* Header row */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", marginBottom: 4, fontSize: 10, color: "#555", fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>
          <span style={{ width: 90 }}>Vecteur</span>
          <span style={{ flex: 1 }}>Payload</span>
          <span style={{ width: 70, textAlign: "center" }}>Verdict</span>
          <span style={{ width: 120, textAlign: "center" }}>Confiance</span>
          <span style={{ width: 80, textAlign: "center" }}>Label</span>
        </div>

        {results.map((r, i) => {
          const label = r.confidence?.label || "possible";
          const value = r.confidence?.value ?? 0;
          const color = CONFIDENCE_COLORS[label] || "#ff9800";
          const isExpanded = expandedIdx === i;
          const isDowngraded = value < CONFIDENCE_THRESHOLD;
          const attack = attackMap[r.vector_id];
          const payload = attack?.payload || r.vector_id || "—";

          return (
            <div key={i} style={{ marginBottom: 4, animation: "fadeIn 0.3s" }}>
              {/* Row */}
              <div onClick={() => setExpandedIdx(isExpanded ? null : i)} style={{
                display: "flex", alignItems: "center", gap: 8, padding: "7px 12px", borderRadius: 6, cursor: "pointer",
                background: isDowngraded ? "#1a0d0d" : `${color}11`,
                borderLeft: `3px solid ${isDowngraded ? "#f44336" : color}`,
                transition: "background 0.2s",
                opacity: isDowngraded ? 0.7 : 1,
              }}>
                <span style={{
                  width: 86, fontSize: 10, fontWeight: 700, fontFamily: "monospace",
                  color: isDowngraded ? "#ef5350" : "#ccc",
                  textDecoration: isDowngraded ? "line-through" : "none",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>{r.vector_id || "—"}</span>

                <code style={{
                  flex: 1, fontSize: 11, color: isDowngraded ? "#666" : "#999",
                  textDecoration: isDowngraded ? "line-through" : "none",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>{payload}</code>

                <span style={{
                  width: 70, textAlign: "center", fontSize: 11,
                  color: r.original_success ? "#4caf50" : "#ef5350",
                }}>{r.original_success ? "Succes" : "Echec"}</span>

                {/* Confidence bar */}
                <div style={{ width: 120, display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ flex: 1, height: 4, borderRadius: 2, background: "#222", overflow: "hidden" }}>
                    <div style={{ width: `${Math.round(value * 100)}%`, height: "100%", borderRadius: 2, background: color, transition: "width 0.5s" }} />
                  </div>
                  <span style={{ fontSize: 10, color, fontWeight: 600, minWidth: 28, textAlign: "right" }}>{Math.round(value * 100)}%</span>
                </div>

                <span style={{
                  width: 76, textAlign: "center", fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                  background: `${color}22`, color, padding: "2px 8px", borderRadius: 10,
                }}>{CONFIDENCE_LABELS[label] || label}</span>

                <span style={{ fontSize: 10, color: "#555", marginLeft: 4 }}>{isExpanded ? "▾" : "▸"}</span>
              </div>

              {/* Downgraded indicator */}
              {isDowngraded && !isExpanded && (
                <div style={{ fontSize: 10, color: "#f44336", paddingLeft: 24, marginTop: 2 }}>
                  Retrograde — confiance insuffisante ({Math.round(value * 100)}% {"<"} {Math.round(CONFIDENCE_THRESHOLD * 100)}%)
                </div>
              )}

              {/* Expanded detail */}
              {isExpanded && (
                <div style={{
                  padding: "10px 16px 10px 24px", marginTop: 2, borderRadius: 6,
                  background: "#0d0d14", borderLeft: `3px solid ${color}`,
                  animation: "fadeIn 0.2s",
                }}>
                  {r.vector_id && (
                    <div style={{ fontSize: 11, color: "#888", marginBottom: 6 }}>
                      <span style={{ color: "#555", fontWeight: 600 }}>Vecteur :</span> {r.vector_id}
                    </div>
                  )}
                  <div style={{ fontSize: 11, color: "#888", marginBottom: 6 }}>
                    <span style={{ color: "#555", fontWeight: 600 }}>Verdict original :</span>{" "}
                    <span style={{ color: r.original_success ? "#4caf50" : "#ef5350" }}>{r.original_success ? "Succes" : "Echec"}</span>
                  </div>
                  <div style={{ fontSize: 11, color: "#888", marginBottom: 6 }}>
                    <span style={{ color: "#555", fontWeight: 600 }}>Score de confiance :</span>{" "}
                    <span style={{ color, fontWeight: 700 }}>{Math.round(value * 100)}%</span>{" "}
                    <span style={{ color: `${color}`, fontSize: 10 }}>({CONFIDENCE_LABELS[label] || label})</span>
                  </div>
                  {isDowngraded && (
                    <div style={{ fontSize: 11, color: "#f44336", marginBottom: 6, fontWeight: 600 }}>
                      Retrograde : la confiance est en dessous du seuil ({Math.round(CONFIDENCE_THRESHOLD * 100)}%)
                    </div>
                  )}
                  {r.details && (
                    <div style={{ fontSize: 11, color: "#999", marginBottom: 6 }}>
                      <span style={{ color: "#555", fontWeight: 600 }}>Details :</span>
                      <div style={{ marginTop: 4, padding: "6px 10px", borderRadius: 4, background: "#111", color: "#ccc", fontSize: 10, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                        {typeof r.details === "string" ? r.details : JSON.stringify(r.details, null, 2)}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </ScrollBox>
    </div>
  );
}
