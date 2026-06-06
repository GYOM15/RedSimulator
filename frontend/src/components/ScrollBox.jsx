/**
 * ScrollBox.jsx — Conteneur avec auto-scroll intelligent
 *
 * - Auto-scroll uniquement si l'utilisateur est deja en bas (seuil 50px)
 * - Bouton flottant "Derniers resultats" quand l'utilisateur remonte
 * - Cliquer le bouton reprend l'auto-scroll
 */

import { useRef, useEffect, useState, useCallback } from "react";

export default function ScrollBox({ children, deps, style }) {
  const ref = useRef(null);
  const [isAtBottom, setIsAtBottom] = useState(true);
  const [showScrollBtn, setShowScrollBtn] = useState(false);

  const checkAtBottom = useCallback(() => {
    const el = ref.current;
    if (!el) return true;
    return el.scrollHeight - el.scrollTop - el.clientHeight < 50;
  }, []);

  const handleScroll = useCallback(() => {
    const atBottom = checkAtBottom();
    setIsAtBottom(atBottom);
    setShowScrollBtn(!atBottom);
  }, [checkAtBottom]);

  // Auto-scroll only when user is at bottom and deps change
  useEffect(() => {
    if (isAtBottom && ref.current) {
      ref.current.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
    }
  }, [deps, isAtBottom]);

  const scrollToBottom = useCallback(() => {
    if (ref.current) {
      ref.current.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
      setIsAtBottom(true);
      setShowScrollBtn(false);
    }
  }, []);

  return (
    <div style={{ position: "relative", flex: 1, minHeight: 0, ...style }}>
      <div
        ref={ref}
        onScroll={handleScroll}
        style={{ maxHeight: 420, overflowY: "auto", paddingRight: 4 }}
      >
        {children}
      </div>
      {showScrollBtn && (
        <button
          onClick={scrollToBottom}
          style={{
            position: "absolute",
            bottom: 12,
            right: 16,
            background: "#e53935",
            border: "none",
            borderRadius: 20,
            padding: "6px 16px",
            color: "#fff",
            fontSize: 11,
            fontWeight: 700,
            cursor: "pointer",
            boxShadow: "0 2px 12px rgba(229,57,53,0.4)",
            display: "flex",
            alignItems: "center",
            gap: 6,
            zIndex: 10,
            transition: "opacity 0.2s",
            fontFamily: "'SF Mono', 'Fira Code', Consolas, monospace",
          }}
        >
          <span style={{ fontSize: 14 }}>&#8595;</span> Derniers resultats
        </button>
      )}
    </div>
  );
}
