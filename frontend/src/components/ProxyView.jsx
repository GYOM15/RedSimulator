/**
 * ProxyView.jsx — MITM proxy control and flow browser
 *
 * Displays start/stop controls, a filterable flow table, and a detail
 * panel for the selected flow.  Follows the same dark theme as the
 * rest of the RedSimulator frontend.
 */

import { useState, useMemo } from "react";
import {
  BG_CARD,
  BG_CARD_DARK,
  BG_ROW_ALT,
  BORDER,
  ACCENT,
  ACCENT_DARK,
  GREEN,
  GREEN_TEXT,
  ORANGE,
  BLUE,
  RED_LIGHT,
  PURPLE,
  STATUS_COLORS,
} from "../styles/theme";

function statusColor(code) {
  if (code >= 200 && code < 300) return STATUS_COLORS["2xx"];
  if (code >= 300 && code < 400) return STATUS_COLORS["3xx"];
  if (code >= 400 && code < 500) return STATUS_COLORS["4xx"];
  if (code >= 500) return STATUS_COLORS["5xx"];
  return "#888";
}

function methodColor(method) {
  const map = { GET: BLUE, POST: GREEN_TEXT, PUT: ORANGE, DELETE: RED_LIGHT, PATCH: PURPLE };
  return map[method?.toUpperCase()] || "#888";
}

function truncate(str, max = 80) {
  if (!str) return "";
  return str.length > max ? str.slice(0, max) + "..." : str;
}

function formatTimestamp(ts) {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return ts;
  }
}

export default function ProxyView({
  proxyStatus,
  flows,
  onStart,
  onStop,
  onReplay,
  onFeed,
  onClear,
  proxyAvailable,
}) {
  const [selectedFlowId, setSelectedFlowId] = useState(null);
  const [filterUrl, setFilterUrl] = useState("");
  const [filterMethod, setFilterMethod] = useState("");
  const [filterStatusMin, setFilterStatusMin] = useState("");
  const [filterStatusMax, setFilterStatusMax] = useState("");

  const selectedFlow = useMemo(
    () => flows.find((f) => f.id === selectedFlowId) || null,
    [flows, selectedFlowId]
  );

  const filteredFlows = useMemo(() => {
    return flows.filter((f) => {
      if (filterUrl && !f.request_url?.toLowerCase().includes(filterUrl.toLowerCase())) return false;
      if (filterMethod && f.request_method?.toUpperCase() !== filterMethod.toUpperCase()) return false;
      if (filterStatusMin && f.response_status < parseInt(filterStatusMin, 10)) return false;
      if (filterStatusMax && f.response_status > parseInt(filterStatusMax, 10)) return false;
      return true;
    });
  }, [flows, filterUrl, filterMethod, filterStatusMin, filterStatusMax]);

  const running = proxyStatus?.running || false;

  const inputStyle = {
    background: BG_CARD_DARK,
    border: `1px solid ${BORDER}`,
    borderRadius: 6,
    padding: "6px 10px",
    color: "#fff",
    fontSize: 12,
    outline: "none",
    fontFamily: "inherit",
  };

  const btnStyle = (bg, color = "#fff") => ({
    background: bg,
    border: "none",
    borderRadius: 6,
    padding: "8px 16px",
    color,
    fontSize: 12,
    fontWeight: 700,
    cursor: "pointer",
    letterSpacing: 0.5,
    transition: "opacity 0.2s",
  });

  // Not available banner
  if (proxyAvailable === false) {
    return (
      <div style={{ padding: 32, textAlign: "center" }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: ORANGE, marginBottom: 12 }}>
          Proxy non disponible
        </div>
        <div style={{ fontSize: 13, color: "#888", lineHeight: 1.8 }}>
          Le module mitmproxy n'est pas installe.<br />
          Installez-le avec : <code style={{ color: ACCENT }}>pip install mitmproxy&gt;=10.0</code>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 110px)", gap: 12 }}>
      {/* Header: status + controls */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          background: BG_CARD,
          borderRadius: 8,
          padding: "12px 16px",
          border: `1px solid ${BORDER}`,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: running ? GREEN : "#555",
              animation: running ? "pulse 1.5s infinite" : "none",
            }}
          />
          <span style={{ fontSize: 13, fontWeight: 600 }}>
            Proxy {running ? "actif" : "arrete"}
          </span>
          {proxyStatus && (
            <span style={{ fontSize: 11, color: "#666" }}>
              {proxyStatus.host}:{proxyStatus.port} | {proxyStatus.flows_count || 0} flux
            </span>
          )}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {!running ? (
            <button onClick={onStart} style={btnStyle(`linear-gradient(135deg, ${ACCENT}, ${ACCENT_DARK})`)}>
              Demarrer
            </button>
          ) : (
            <button onClick={onStop} style={btnStyle("#333", "#ccc")}>
              Arreter
            </button>
          )}
          <button
            onClick={onFeed}
            style={btnStyle(GREEN, "#fff")}
            title="Injecter les flux captures dans le pipeline"
          >
            Feed Pipeline
          </button>
          <button
            onClick={onClear}
            style={btnStyle("#333", "#888")}
            title="Supprimer tous les flux captures"
          >
            Vider
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div
        style={{
          display: "flex",
          gap: 8,
          alignItems: "center",
          background: BG_CARD,
          borderRadius: 8,
          padding: "8px 12px",
          border: `1px solid ${BORDER}`,
        }}
      >
        <span style={{ fontSize: 11, color: "#666", fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>
          Filtres
        </span>
        <input
          placeholder="URL..."
          value={filterUrl}
          onChange={(e) => setFilterUrl(e.target.value)}
          style={{ ...inputStyle, flex: 1, minWidth: 120 }}
        />
        <select
          value={filterMethod}
          onChange={(e) => setFilterMethod(e.target.value)}
          style={{ ...inputStyle, minWidth: 80 }}
        >
          <option value="">Methode</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
          <option value="PATCH">PATCH</option>
          <option value="OPTIONS">OPTIONS</option>
          <option value="HEAD">HEAD</option>
        </select>
        <input
          placeholder="Status min"
          value={filterStatusMin}
          onChange={(e) => setFilterStatusMin(e.target.value)}
          style={{ ...inputStyle, width: 80 }}
          type="number"
        />
        <input
          placeholder="Status max"
          value={filterStatusMax}
          onChange={(e) => setFilterStatusMax(e.target.value)}
          style={{ ...inputStyle, width: 80 }}
          type="number"
        />
        <span style={{ fontSize: 11, color: "#555" }}>
          {filteredFlows.length} / {flows.length}
        </span>
      </div>

      {/* Main area: table + detail */}
      <div style={{ flex: 1, display: "flex", gap: 12, overflow: "hidden" }}>
        {/* Flow table */}
        <div
          style={{
            flex: selectedFlow ? 1 : 1,
            overflowY: "auto",
            background: BG_CARD,
            borderRadius: 8,
            border: `1px solid ${BORDER}`,
          }}
        >
          {/* Table header */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "70px 60px 1fr 60px 70px 120px",
              gap: 4,
              padding: "8px 12px",
              borderBottom: `1px solid ${BORDER}`,
              fontSize: 10,
              fontWeight: 700,
              color: "#555",
              letterSpacing: 1,
              textTransform: "uppercase",
              position: "sticky",
              top: 0,
              background: BG_CARD,
              zIndex: 1,
            }}
          >
            <span>Heure</span>
            <span>Methode</span>
            <span>URL</span>
            <span>Status</span>
            <span>Duree</span>
            <span>Type</span>
          </div>

          {filteredFlows.length === 0 ? (
            <div style={{ padding: 32, textAlign: "center", color: "#555", fontSize: 13 }}>
              {flows.length === 0
                ? "Aucun flux capture. Demarrez le proxy et naviguez sur un site."
                : "Aucun flux ne correspond aux filtres."}
            </div>
          ) : (
            filteredFlows.map((flow, idx) => (
              <div
                key={flow.id}
                onClick={() => setSelectedFlowId(flow.id === selectedFlowId ? null : flow.id)}
                style={{
                  display: "grid",
                  gridTemplateColumns: "70px 60px 1fr 60px 70px 120px",
                  gap: 4,
                  padding: "6px 12px",
                  fontSize: 11,
                  cursor: "pointer",
                  background:
                    flow.id === selectedFlowId
                      ? `${ACCENT}15`
                      : idx % 2 === 0
                      ? "transparent"
                      : BG_ROW_ALT,
                  borderLeft:
                    flow.id === selectedFlowId ? `3px solid ${ACCENT}` : "3px solid transparent",
                  transition: "background 0.15s",
                }}
              >
                <span style={{ color: "#666" }}>{formatTimestamp(flow.timestamp)}</span>
                <span style={{ color: methodColor(flow.request_method), fontWeight: 700 }}>
                  {flow.request_method}
                </span>
                <span
                  style={{
                    color: "#ccc",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={flow.request_url}
                >
                  {flow.request_path || flow.request_url}
                </span>
                <span style={{ color: statusColor(flow.response_status), fontWeight: 600 }}>
                  {flow.response_status || "-"}
                </span>
                <span style={{ color: "#888" }}>
                  {flow.duration_ms ? `${Math.round(flow.duration_ms)}ms` : "-"}
                </span>
                <span
                  style={{
                    color: "#666",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {flow.response_content_type?.split(";")[0] || "-"}
                </span>
              </div>
            ))
          )}
        </div>

        {/* Detail panel */}
        {selectedFlow && (
          <div
            style={{
              width: 420,
              flexShrink: 0,
              overflowY: "auto",
              background: BG_CARD,
              borderRadius: 8,
              border: `1px solid ${BORDER}`,
              padding: 16,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: 12,
              }}
            >
              <div style={{ fontSize: 13, fontWeight: 700 }}>Detail du flux</div>
              <button
                onClick={() => onReplay && onReplay(selectedFlow.id)}
                style={btnStyle(ACCENT)}
                title="Rejouer cette requete"
              >
                Rejouer
              </button>
            </div>

            {/* Request */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: BLUE, marginBottom: 6, letterSpacing: 1, textTransform: "uppercase" }}>
                Requete
              </div>
              <div style={{ fontSize: 12, marginBottom: 4 }}>
                <span style={{ color: methodColor(selectedFlow.request_method), fontWeight: 700 }}>
                  {selectedFlow.request_method}
                </span>{" "}
                <span style={{ color: "#ccc", wordBreak: "break-all" }}>{selectedFlow.request_url}</span>
              </div>
              <div style={{ fontSize: 11, color: "#666", marginBottom: 4 }}>
                Host: {selectedFlow.request_host}
              </div>

              {/* Request headers */}
              <details style={{ marginTop: 8 }}>
                <summary style={{ fontSize: 11, color: "#888", cursor: "pointer" }}>
                  En-tetes ({Object.keys(selectedFlow.request_headers || {}).length})
                </summary>
                <div
                  style={{
                    background: BG_CARD_DARK,
                    borderRadius: 4,
                    padding: 8,
                    marginTop: 4,
                    fontSize: 10,
                    lineHeight: 1.6,
                    maxHeight: 200,
                    overflowY: "auto",
                  }}
                >
                  {Object.entries(selectedFlow.request_headers || {}).map(([k, v]) => (
                    <div key={k}>
                      <span style={{ color: ORANGE }}>{k}</span>: <span style={{ color: "#aaa" }}>{v}</span>
                    </div>
                  ))}
                </div>
              </details>

              {/* Request body */}
              {selectedFlow.request_body && (
                <details style={{ marginTop: 8 }}>
                  <summary style={{ fontSize: 11, color: "#888", cursor: "pointer" }}>Corps de la requete</summary>
                  <pre
                    style={{
                      background: BG_CARD_DARK,
                      borderRadius: 4,
                      padding: 8,
                      marginTop: 4,
                      fontSize: 10,
                      lineHeight: 1.4,
                      maxHeight: 200,
                      overflowY: "auto",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                      color: "#aaa",
                    }}
                  >
                    {selectedFlow.request_body}
                  </pre>
                </details>
              )}
            </div>

            {/* Response */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: GREEN_TEXT, marginBottom: 6, letterSpacing: 1, textTransform: "uppercase" }}>
                Reponse
              </div>
              <div style={{ fontSize: 12, marginBottom: 4 }}>
                Status:{" "}
                <span style={{ color: statusColor(selectedFlow.response_status), fontWeight: 700 }}>
                  {selectedFlow.response_status}
                </span>
                <span style={{ color: "#666", marginLeft: 8 }}>
                  {selectedFlow.response_content_type}
                </span>
                <span style={{ color: "#666", marginLeft: 8 }}>
                  {selectedFlow.duration_ms ? `${Math.round(selectedFlow.duration_ms)}ms` : ""}
                </span>
              </div>

              {/* Response headers */}
              <details style={{ marginTop: 8 }}>
                <summary style={{ fontSize: 11, color: "#888", cursor: "pointer" }}>
                  En-tetes ({Object.keys(selectedFlow.response_headers || {}).length})
                </summary>
                <div
                  style={{
                    background: BG_CARD_DARK,
                    borderRadius: 4,
                    padding: 8,
                    marginTop: 4,
                    fontSize: 10,
                    lineHeight: 1.6,
                    maxHeight: 200,
                    overflowY: "auto",
                  }}
                >
                  {Object.entries(selectedFlow.response_headers || {}).map(([k, v]) => (
                    <div key={k}>
                      <span style={{ color: ORANGE }}>{k}</span>: <span style={{ color: "#aaa" }}>{v}</span>
                    </div>
                  ))}
                </div>
              </details>

              {/* Response body */}
              {selectedFlow.response_body && (
                <details style={{ marginTop: 8 }}>
                  <summary style={{ fontSize: 11, color: "#888", cursor: "pointer" }}>Corps de la reponse</summary>
                  <pre
                    style={{
                      background: BG_CARD_DARK,
                      borderRadius: 4,
                      padding: 8,
                      marginTop: 4,
                      fontSize: 10,
                      lineHeight: 1.4,
                      maxHeight: 300,
                      overflowY: "auto",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                      color: "#aaa",
                    }}
                  >
                    {truncate(selectedFlow.response_body, 5000)}
                  </pre>
                </details>
              )}
            </div>

            {/* Tags */}
            {selectedFlow.tags && selectedFlow.tags.length > 0 && (
              <div style={{ marginTop: 12, display: "flex", gap: 4, flexWrap: "wrap" }}>
                {selectedFlow.tags.map((tag) => (
                  <span
                    key={tag}
                    style={{
                      background: `${ACCENT}20`,
                      color: ACCENT,
                      fontSize: 10,
                      padding: "2px 8px",
                      borderRadius: 4,
                    }}
                  >
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
