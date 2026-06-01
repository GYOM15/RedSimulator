/**
 * ScrollBox.jsx — Conteneur avec auto-scroll
 */

import { useRef, useEffect } from "react";

export default function ScrollBox({ children, deps }) {
  const ref = useRef(null);
  useEffect(() => { ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" }); }, [deps]);
  return <div ref={ref} style={{ maxHeight: 420, overflowY: "auto", paddingRight: 4 }}>{children}</div>;
}
