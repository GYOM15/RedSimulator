/**
 * theme.js — Couleurs et constantes visuelles partagees
 */

export const BG = "#09090f";
export const BG_CARD = "#1a1a2e";
export const BG_CARD_DARK = "#0f0f17";
export const BG_ROW_ALT = "#0d0d14";
export const BORDER = "#1e1e2e";
export const ACCENT = "#e53935";
export const ACCENT_DARK = "#c62828";
export const GREEN = "#2e7d32";
export const GREEN_LIGHT = "#4caf50";
export const GREEN_TEXT = "#66bb6a";
export const GREEN_BG = "#0d1a0d";
export const GREEN_DARK = "#1b5e20";
export const GREEN_SOFT = "#a5d6a7";
export const ORANGE = "#ffa726";
export const ORANGE_LIGHT = "#ffcc80";
export const PURPLE = "#ab47bc";
export const PURPLE_LIGHT = "#ce93d8";
export const PURPLE_BG = "#1a1020";
export const PURPLE_DARK = "#2a1a35";
export const BLUE = "#42a5f5";
export const BLUE_LIGHT = "#90caf9";
export const RED_DARK = "#b71c1c";
export const RED_LIGHT = "#ef5350";
export const RED_SOFT = "#ef9a9a";

export const SEV = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#16a34a",
};

export const STATUS_COLORS = {
  "2xx": "#4caf50",
  "3xx": "#ff9800",
  "4xx": "#f44336",
  "5xx": "#9c27b0",
};

export const API = "/api";

export const CONFIDENCE_COLORS = {
  confirmed: '#4caf50',
  likely: '#8bc34a',
  possible: '#ff9800',
  unlikely: '#ff5722',
  false_positive: '#f44336',
};

export const CWE_SEVERITY_COLORS = {
  CRITICAL: '#f44336',
  HIGH: '#ff5722',
  MEDIUM: '#ff9800',
  LOW: '#2196f3',
  INFO: '#9e9e9e',
};

export const STEPS = [
  { id: "scanning", name: "Scanner", tech: "Agent ReAct" },
  { id: "passive", name: "Passif", tech: "Scan passif" },
  { id: "expert", name: "Analyseur", tech: "Systeme expert" },
  { id: "generator", name: "Generateur", tech: "LLM + Offline" },
  { id: "attacking", name: "Executeur", tech: "Attaques" },
  { id: "validation", name: "Validation", tech: "Confiance" },
  { id: "reporting", name: "Rapporteur", tech: "LLM" },
];
