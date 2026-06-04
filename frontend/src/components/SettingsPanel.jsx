/**
 * SettingsPanel.jsx — Modal de configuration LLM
 *
 * Securite : la cle API n'est JAMAIS persistee cote client
 * (ni localStorage, ni sessionStorage, ni cookie).
 * Elle vit uniquement dans un useState React et est effacee
 * immediatement apres envoi au backend.
 */

import { useState, useEffect } from "react";
import {
  BG, BG_CARD, BORDER, ACCENT, ACCENT_DARK,
  GREEN, GREEN_TEXT, GREEN_BG,
  ORANGE, BLUE, BLUE_LIGHT,
} from "../styles/theme";

/* ---------- tiny SVG icons (inline to avoid extra deps) ---------- */

const EyeIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const EyeOffIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

const GearIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </svg>
);

/* ---------- Provider metadata (fallback when backend list empty) ---------- */

const DEFAULT_PROVIDERS = [
  { id: "anthropic", name: "Anthropic (Claude)", requires_key: true },
  { id: "openai", name: "OpenAI", requires_key: true },
  { id: "ollama", name: "Ollama (local)", requires_key: false },
];

const PROVIDER_PLACEHOLDER = {
  anthropic: "sk-ant-...",
  openai: "sk-...",
};

/* ====================================================================== */

export { GearIcon };

export default function SettingsPanel({ isOpen, onClose, llmConfig, onSave, onClear }) {
  /* ---- local form state ---- */
  const [provider, setProvider] = useState(llmConfig?.provider || "anthropic");
  const [model, setModel] = useState(llmConfig?.model || "");
  const [apiKey, setApiKey] = useState(""); // NEVER pre-filled, NEVER persisted
  const [ollamaUrl, setOllamaUrl] = useState(llmConfig?.ollama_url || "http://localhost:11434");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [customModel, setCustomModel] = useState(false);

  /* Sync when the config changes from backend */
  useEffect(() => {
    if (llmConfig) {
      setProvider(llmConfig.provider || "anthropic");
      setModel(llmConfig.model || "");
      setOllamaUrl(llmConfig.ollama_url || "http://localhost:11434");
    }
  }, [llmConfig]);

  /* ---- derived ---- */
  const providers = llmConfig?.available_providers?.length
    ? llmConfig.available_providers
    : DEFAULT_PROVIDERS;

  const suggestedModels = llmConfig?.suggested_models || {};
  const currentProvider = providers.find((p) => p.id === provider);
  const requiresKey = currentProvider?.requires_key ?? true;
  const modelsForProvider = suggestedModels[provider] || [];

  /* ---- handlers ---- */
  const handleSave = async () => {
    setSaving(true);
    setError("");
    try {
      const payload = { provider, model };
      if (requiresKey && apiKey) payload.api_key = apiKey;
      if (provider === "ollama") payload.ollama_url = ollamaUrl;
      await onSave(payload);
      setApiKey(""); // CLEAR the key from state immediately after sending
      onClose();
    } catch (e) {
      setError(e.message || "Failed to save configuration");
    }
    setSaving(false);
  };

  const handleClear = async () => {
    setSaving(true);
    setError("");
    try {
      await onClear();
      setApiKey("");
      setModel("");
      setProvider("anthropic");
      onClose();
    } catch (e) {
      setError(e.message || "Failed to clear configuration");
    }
    setSaving(false);
  };

  /* ---- early return ---- */
  if (!isOpen) return null;

  /* ---- styles (inline to match the project pattern) ---- */
  const overlay = {
    position: "fixed", inset: 0, zIndex: 9999,
    background: "rgba(0,0,0,0.65)", backdropFilter: "blur(4px)",
    display: "flex", alignItems: "center", justifyContent: "center",
    animation: "fadeIn 0.2s ease",
  };

  const card = {
    background: BG_CARD, border: `1px solid ${BORDER}`, borderRadius: 12,
    padding: 28, width: 480, maxHeight: "85vh", overflowY: "auto",
    boxShadow: "0 12px 48px rgba(0,0,0,0.6)",
  };

  const label = { fontSize: 11, fontWeight: 700, letterSpacing: 1.5, color: "#888", textTransform: "uppercase", marginBottom: 8 };

  const inputStyle = {
    width: "100%", boxSizing: "border-box",
    background: BG, border: `1px solid ${BORDER}`, borderRadius: 8,
    padding: "10px 14px", color: "#fff", fontSize: 13,
    fontFamily: "'SF Mono', 'Fira Code', Consolas, monospace",
    outline: "none",
  };

  const btnPrimary = {
    flex: 1, background: `linear-gradient(135deg, ${ACCENT}, ${ACCENT_DARK})`,
    border: "none", borderRadius: 8, padding: "10px 20px",
    color: "#fff", fontSize: 13, fontWeight: 700, cursor: "pointer",
    letterSpacing: 1, opacity: saving ? 0.6 : 1,
  };

  const btnSecondary = {
    flex: 1, background: "transparent", border: `1px solid ${BORDER}`,
    borderRadius: 8, padding: "10px 20px",
    color: "#888", fontSize: 13, fontWeight: 600, cursor: "pointer",
  };

  const btnDanger = {
    background: "transparent", border: `1px solid ${ACCENT}`,
    borderRadius: 8, padding: "10px 20px",
    color: ACCENT, fontSize: 12, fontWeight: 600, cursor: "pointer",
  };

  /* ================================================================ */
  return (
    <div style={overlay} onClick={onClose}>
      <div style={card} onClick={(e) => e.stopPropagation()}>

        {/* ---------- Header ---------- */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <GearIcon />
            <span style={{ fontSize: 16, fontWeight: 700 }}>Configuration LLM</span>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#555", fontSize: 20, cursor: "pointer", lineHeight: 1 }}>
            &#x2715;
          </button>
        </div>

        {/* ---------- Provider selector ---------- */}
        <div style={{ marginBottom: 20 }}>
          <div style={label}>Fournisseur</div>
          <div style={{ display: "flex", gap: 8 }}>
            {providers.map((p) => {
              const selected = p.id === provider;
              return (
                <button key={p.id} onClick={() => { setProvider(p.id); setModel(""); setCustomModel(false); }}
                  style={{
                    flex: 1, background: selected ? "#252540" : BG,
                    border: `1px solid ${selected ? ACCENT : BORDER}`,
                    borderRadius: 8, padding: "10px 8px", cursor: "pointer",
                    display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
                    transition: "all 0.2s",
                  }}
                >
                  <span style={{ fontSize: 13, fontWeight: 600, color: selected ? "#fff" : "#888" }}>{p.name}</span>
                  {p.requires_key
                    ? <span style={{ fontSize: 9, color: ORANGE, letterSpacing: 1 }}>CLE REQUISE</span>
                    : <span style={{ fontSize: 9, color: GREEN_TEXT, letterSpacing: 1 }}>LOCAL</span>}
                </button>
              );
            })}
          </div>
        </div>

        {/* ---------- Model selector ---------- */}
        <div style={{ marginBottom: 20 }}>
          <div style={label}>Modele</div>
          {modelsForProvider.length > 0 && !customModel ? (
            <div>
              <select value={model} onChange={(e) => setModel(e.target.value)}
                style={{ ...inputStyle, cursor: "pointer", appearance: "auto" }}
              >
                <option value="">-- Choisir un modele --</option>
                {modelsForProvider.map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
              <button onClick={() => setCustomModel(true)}
                style={{ background: "none", border: "none", color: BLUE, fontSize: 11, cursor: "pointer", marginTop: 6, padding: 0 }}
              >
                Entrer un modele personnalise
              </button>
            </div>
          ) : (
            <div>
              <input value={model} onChange={(e) => setModel(e.target.value)}
                placeholder="ex: claude-sonnet-4-20250514"
                style={inputStyle}
              />
              {modelsForProvider.length > 0 && (
                <button onClick={() => { setCustomModel(false); setModel(""); }}
                  style={{ background: "none", border: "none", color: BLUE, fontSize: 11, cursor: "pointer", marginTop: 6, padding: 0 }}
                >
                  Choisir parmi les modeles suggeres
                </button>
              )}
            </div>
          )}
        </div>

        {/* ---------- API Key (cloud providers only) ---------- */}
        {requiresKey && (
          <div style={{ marginBottom: 20 }}>
            <div style={label}>Cle API</div>

            {/* Current status indicator */}
            {llmConfig?.api_key_set && !apiKey && (
              <div style={{
                display: "flex", alignItems: "center", gap: 8,
                background: GREEN_BG, border: `1px solid ${GREEN}`,
                borderRadius: 8, padding: "8px 12px", marginBottom: 10, fontSize: 12,
              }}>
                <span style={{ color: GREEN_TEXT, fontSize: 16 }}>&#x2713;</span>
                <span style={{ color: GREEN_TEXT }}>Cle API configuree</span>
              </div>
            )}

            {!llmConfig?.api_key_set && !apiKey && (
              <div style={{
                display: "flex", alignItems: "center", gap: 8,
                background: "#1a0d0d", border: `1px solid ${ACCENT}`,
                borderRadius: 8, padding: "8px 12px", marginBottom: 10, fontSize: 12,
              }}>
                <span style={{ color: ACCENT, fontSize: 16 }}>&#x26A0;</span>
                <span style={{ color: "#ef9a9a" }}>Cle API non configuree</span>
              </div>
            )}

            {/* Password input with toggle */}
            <div style={{ position: "relative" }}>
              <input
                type={showKey ? "text" : "password"}
                autoComplete="off"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={llmConfig?.api_key_set ? "Entrer une nouvelle cle pour remplacer" : (PROVIDER_PLACEHOLDER[provider] || "Entrer la cle API")}
                style={{ ...inputStyle, paddingRight: 42 }}
              />
              <button onClick={() => setShowKey(!showKey)}
                style={{
                  position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)",
                  background: "none", border: "none", color: "#555", cursor: "pointer",
                  display: "flex", alignItems: "center",
                }}
              >
                {showKey ? <EyeOffIcon /> : <EyeIcon />}
              </button>
            </div>

            {/* Security notice */}
            <div style={{
              marginTop: 10, padding: "8px 12px",
              background: "#0d0d1a", border: `1px solid #1e1e3e`, borderRadius: 6,
              fontSize: 10, color: "#556", lineHeight: 1.5,
              display: "flex", alignItems: "flex-start", gap: 8,
            }}>
              <span style={{ color: BLUE, fontSize: 14, flexShrink: 0, marginTop: -1 }}>&#x1F512;</span>
              <span>
                Votre cle API est conservee uniquement en memoire et n'est jamais
                sauvegardee sur le disque, dans le navigateur ou dans les cookies.
                Elle sera effacee si vous rafraichissez la page.
              </span>
            </div>
          </div>
        )}

        {/* ---------- Ollama URL (ollama provider only) ---------- */}
        {provider === "ollama" && (
          <div style={{ marginBottom: 20 }}>
            <div style={label}>URL Ollama</div>
            <input value={ollamaUrl} onChange={(e) => setOllamaUrl(e.target.value)}
              placeholder="http://localhost:11434"
              style={inputStyle}
            />
          </div>
        )}

        {/* ---------- Error ---------- */}
        {error && (
          <div style={{
            background: "#1a0d0d", border: `1px solid ${ACCENT}`, borderRadius: 8,
            padding: "10px 14px", marginBottom: 16, fontSize: 12, color: "#ef9a9a",
          }}>
            {error}
          </div>
        )}

        {/* ---------- Actions ---------- */}
        <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
          <button onClick={handleSave} disabled={saving} style={btnPrimary}>
            {saving ? "Enregistrement..." : "Enregistrer"}
          </button>
          <button onClick={onClose} style={btnSecondary}>Annuler</button>
        </div>

        {(llmConfig?.api_key_set || llmConfig?.provider) && (
          <button onClick={handleClear} disabled={saving} style={{ ...btnDanger, width: "100%" }}>
            Effacer la configuration
          </button>
        )}
      </div>
    </div>
  );
}
