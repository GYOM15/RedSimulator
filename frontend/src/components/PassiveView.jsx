/**
 * PassiveView.jsx — Vue des resultats du scan passif
 */

import { useState } from "react";
import ScrollBox from "./ScrollBox";
import { CWE_SEVERITY_COLORS, BG_CARD } from "../styles/theme";

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function PassiveView({ findings }) {
  const [expandedIdx, setExpandedIdx] = useState(null);

  if (!findings || findings.length === 0) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 300, color: "#555", fontSize: 14 }}>
        Aucune decouverte passive pour le moment.
      </div>
    );
  }

  // Group by severity
  const grouped = {};
  for (const sev of SEVERITY_ORDER) grouped[sev] = [];
  for (const f of findings) {
    const sev = (f.severity || "INFO").toUpperCase();
    if (!grouped[sev]) grouped[sev] = [];
    grouped[sev].push(f);
  }

  const total = findings.length;

  return (
    <div>
      {/* Stat cards */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        {SEVERITY_ORDER.map((sev) => (
          <div key={sev} style={{ background: BG_CARD, borderRadius: 8, padding: "12px 20px", flex: 1, textAlign: "center" }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: CWE_SEVERITY_COLORS[sev] }}>{grouped[sev].length}</div>
            <div style={{ fontSize: 10, color: "#888", letterSpacing: 1, textTransform: "uppercase" }}>{sev}</div>
          </div>
        ))}
      </div>

      {/* Severity distribution bar */}
      <div style={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", marginBottom: 16 }}>
        {SEVERITY_ORDER.map((sev) => {
          const count = grouped[sev].length;
          if (count === 0) return null;
          return (
            <div key={sev} style={{ flex: count, background: CWE_SEVERITY_COLORS[sev], transition: "flex 0.5s" }}
              title={`${sev}: ${count}`} />
          );
        })}
      </div>

      {/* Findings table */}
      <ScrollBox deps={[findings.length, expandedIdx]}>
        {/* Header row */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", marginBottom: 4, fontSize: 10, color: "#555", fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>
          <span style={{ width: 72 }}>Severite</span>
          <span style={{ flex: 1 }}>Titre</span>
          <span style={{ width: 180 }}>URL</span>
          <span style={{ width: 70, textAlign: "center" }}>CWE</span>
        </div>

        {findings.map((f, i) => {
          const sev = (f.severity || "INFO").toUpperCase();
          const color = CWE_SEVERITY_COLORS[sev] || "#9e9e9e";
          const isExpanded = expandedIdx === i;

          return (
            <div key={i} style={{ marginBottom: 4, animation: "fadeIn 0.3s" }}>
              {/* Row */}
              <div onClick={() => setExpandedIdx(isExpanded ? null : i)} style={{
                display: "flex", alignItems: "center", gap: 8, padding: "7px 12px", borderRadius: 6, cursor: "pointer",
                background: `${color}11`, borderLeft: `3px solid ${color}`,
                transition: "background 0.2s",
              }}>
                <span style={{
                  width: 68, fontSize: 10, fontWeight: 700, textTransform: "uppercase", textAlign: "center",
                  background: `${color}22`, color, padding: "2px 8px", borderRadius: 10,
                }}>{sev}</span>
                <span style={{ flex: 1, fontSize: 12, color: "#ccc", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {f.title || f.check_name || "—"}
                </span>
                <code style={{ width: 180, fontSize: 10, color: "#666", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {f.url || "—"}
                </code>
                <span style={{ width: 70, textAlign: "center" }}>
                  {f.cwe_id ? (
                    <a href={`https://cwe.mitre.org/data/definitions/${f.cwe_id}.html`} target="_blank" rel="noopener noreferrer"
                      style={{ fontSize: 10, color: "#42a5f5", textDecoration: "none" }}
                      onClick={(e) => e.stopPropagation()}>
                      CWE-{f.cwe_id}
                    </a>
                  ) : <span style={{ fontSize: 10, color: "#444" }}>—</span>}
                </span>
                <span style={{ fontSize: 10, color: "#555", marginLeft: 4 }}>{isExpanded ? "▾" : "▸"}</span>
              </div>

              {/* Expanded detail */}
              {isExpanded && (
                <div style={{
                  padding: "10px 16px 10px 24px", marginTop: 2, borderRadius: 6,
                  background: "#0d0d14", borderLeft: `3px solid ${color}`,
                  animation: "fadeIn 0.2s",
                }}>
                  {f.check_name && (
                    <div style={{ fontSize: 11, color: "#888", marginBottom: 6 }}>
                      <span style={{ color: "#555", fontWeight: 600 }}>Check :</span> {f.check_name}
                    </div>
                  )}
                  {f.description && (
                    <div style={{ fontSize: 11, color: "#999", marginBottom: 6 }}>
                      <span style={{ color: "#555", fontWeight: 600 }}>Description :</span> {f.description}
                    </div>
                  )}
                  {f.evidence && (
                    <div style={{ fontSize: 11, marginBottom: 6 }}>
                      <span style={{ color: "#555", fontWeight: 600 }}>Evidence :</span>
                      <code style={{ display: "block", marginTop: 4, padding: "6px 10px", borderRadius: 4, background: "#111", color: "#ef9a9a", fontSize: 10, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                        {f.evidence}
                      </code>
                    </div>
                  )}
                  {f.remediation && (
                    <div style={{ fontSize: 11, color: "#66bb6a" }}>
                      <span style={{ color: "#555", fontWeight: 600 }}>Remediation :</span> {f.remediation}
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
