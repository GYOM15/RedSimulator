#!/bin/bash
# Telecharge les wordlists SecLists essentielles pour la reconnaissance.
# Source: https://github.com/danielmiessler/SecLists
#
# Usage: bash scripts/setup_wordlists.sh

set -e

WORDLIST_DIR="$(cd "$(dirname "$0")/../data/wordlists" && pwd)"
SECLISTS_RAW="https://raw.githubusercontent.com/danielmiessler/SecLists/master"

echo "=== Setup des wordlists SecLists ==="
echo "Destination: $WORDLIST_DIR"
echo ""

mkdir -p "$WORDLIST_DIR/seclists"

# --- Web Content Discovery ---
echo "[1/5] Web content (common.txt — 4700 chemins)..."
curl -sL "$SECLISTS_RAW/Discovery/Web-Content/common.txt" \
    -o "$WORDLIST_DIR/seclists/web-common.txt"
wc -l < "$WORDLIST_DIR/seclists/web-common.txt" | xargs -I{} echo "  {} chemins"

echo "[2/5] Web content (raft-medium-directories — 30000 chemins)..."
curl -sL "$SECLISTS_RAW/Discovery/Web-Content/raft-medium-directories.txt" \
    -o "$WORDLIST_DIR/seclists/web-directories.txt"
wc -l < "$WORDLIST_DIR/seclists/web-directories.txt" | xargs -I{} echo "  {} chemins"

echo "[3/5] Web content (raft-medium-files — 17000 chemins)..."
curl -sL "$SECLISTS_RAW/Discovery/Web-Content/raft-medium-files.txt" \
    -o "$WORDLIST_DIR/seclists/web-files.txt"
wc -l < "$WORDLIST_DIR/seclists/web-files.txt" | xargs -I{} echo "  {} chemins"

# --- DNS Subdomains ---
echo "[4/5] DNS subdomains (top 5000)..."
curl -sL "$SECLISTS_RAW/Discovery/DNS/subdomains-top1million-5000.txt" \
    -o "$WORDLIST_DIR/seclists/dns-subdomains.txt"
wc -l < "$WORDLIST_DIR/seclists/dns-subdomains.txt" | xargs -I{} echo "  {} sous-domaines"

# --- API Discovery ---
echo "[5/5] API endpoints..."
curl -sL "$SECLISTS_RAW/Discovery/Web-Content/api/api-endpoints.txt" \
    -o "$WORDLIST_DIR/seclists/api-endpoints.txt" 2>/dev/null || \
curl -sL "$SECLISTS_RAW/Discovery/Web-Content/api/objects.txt" \
    -o "$WORDLIST_DIR/seclists/api-endpoints.txt" 2>/dev/null || \
echo "  (API endpoints non disponible, on garde nos listes custom)"
[ -f "$WORDLIST_DIR/seclists/api-endpoints.txt" ] && \
    wc -l < "$WORDLIST_DIR/seclists/api-endpoints.txt" | xargs -I{} echo "  {} endpoints API"

echo ""
echo "=== Termine ==="
echo "Wordlists disponibles:"
ls -lh "$WORDLIST_DIR/seclists/"
echo ""
echo "Les wordlists custom (common.txt, sensitive.txt, etc.) sont conservees."
