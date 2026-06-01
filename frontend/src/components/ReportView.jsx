/**
 * ReportView.jsx — Affichage du rapport en temps reel
 */

import { useRef, useEffect } from "react";
import { Md } from "./Markdown";

export default function ReportView({ text }) {
  const ref = useRef(null);
  useEffect(() => { ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" }); }, [text]);
  return (
    <div ref={ref} style={{ maxHeight: 440, overflowY: "auto", padding: "0 8px" }}>
      <Md text={text} />
      {text && <span style={{ animation: "blink 1s infinite", color: "#e53935" }}>{"█"}</span>}
    </div>
  );
}
