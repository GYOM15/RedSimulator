/**
 * Markdown.jsx — Rendu Markdown simplifie (Md, MdTable, InlineText)
 */

import { SEV } from "../styles/theme";

export function InlineText({ text }) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((p, j) => {
    if (p.startsWith("**")) return <b key={j} style={{ color: "#fff" }}>{p.slice(2, -2)}</b>;
    if (p.startsWith("`")) return <code key={j} style={{ background: "#1a1a2e", padding: "1px 5px", borderRadius: 3, fontSize: 11, color: "#ef9a9a" }}>{p.slice(1, -1)}</code>;
    return <span key={j}>{p}</span>;
  });
}

export function MdTable({ rows }) {
  const parsed = rows.map(r => r.split("|").filter(c => c.trim()).map(c => c.trim()));
  if (parsed.length < 2) return null;
  const header = parsed[0];
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

export function Md({ text }) {
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

    // Table
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
    if (line.startsWith("- ")) { elements.push(<div key={i} style={{ paddingLeft: 16, marginBottom: 2, fontSize: 12 }}>{"▸"} <InlineText text={line.slice(2)} /></div>); i++; continue; }

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
