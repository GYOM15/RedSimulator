"""Service API pour les outils de reconnaissance Docker.

Expose nmap, ffuf et subfinder via des endpoints REST.
Un seul conteneur Docker pour tous les outils.

Endpoints:
    GET /scan?host=...&ports=...       — Scan de ports (nmap)
    GET /bruteforce?url=...&wordlist=... — Directory bruteforce (ffuf)
    GET /dns?domain=...                — Enumeration DNS (subfinder)
    GET /health                        — Health check
"""

import json
import os
import subprocess
import tempfile

import nmap
from flask import Flask, jsonify, request

app = Flask(__name__)

WORDLISTS_DIR = "/app/wordlists"


@app.route("/health")
def health():
    """Health check avec versions des outils."""
    tools = {}
    for tool, cmd in [("nmap", "nmap --version"), ("ffuf", "ffuf -V"), ("subfinder", "subfinder -version")]:
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            tools[tool] = "disponible"
        except Exception:
            tools[tool] = "indisponible"

    return jsonify({"status": "ok", "tools": tools})


@app.route("/scan")
def scan():
    """Scan de ports avec nmap."""
    host = request.args.get("host", "")
    ports = request.args.get("ports", "21,22,80,443,3000,8080")

    if not host:
        return jsonify({"error": "Parametre 'host' requis"}), 400

    try:
        nm = nmap.PortScanner()
        nm.scan(host, ports, arguments="-sV --version-intensity 2")

        results = []
        if host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    state = nm[host][proto][port]
                    if state["state"] == "open":
                        results.append({
                            "port": port,
                            "service": state.get("name", "unknown"),
                            "version": f"{state.get('product', '')} {state.get('version', '')}".strip() or None,
                        })

        return jsonify({"host": host, "results": results})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/bruteforce")
def bruteforce():
    """Directory bruteforce avec ffuf."""
    url = request.args.get("url", "")
    wordlist = request.args.get("wordlist", "seclists/web-common")

    if not url:
        return jsonify({"error": "Parametre 'url' requis"}), 400

    # Trouver la wordlist
    wordlist_path = os.path.join(WORDLISTS_DIR, f"{wordlist}.txt")
    if not os.path.exists(wordlist_path):
        available = []
        for root, dirs, files in os.walk(WORDLISTS_DIR):
            for f in files:
                if f.endswith(".txt"):
                    rel = os.path.relpath(os.path.join(root, f), WORDLISTS_DIR)
                    available.append(rel.replace(".txt", ""))
        return jsonify({"error": f"Wordlist '{wordlist}' non trouvee", "available": available}), 400

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        target_url = url.rstrip("/") + "/FUZZ"

        cmd = [
            "ffuf",
            "-u", target_url,
            "-w", wordlist_path,
            "-o", tmp_path,
            "-of", "json",
            "-ac",                    # Auto-calibration soft-404
            "-t", "20",               # 20 threads (dans Docker c'est safe)
            "-timeout", "3",
            "-mc", "200,201,301,302,401,403",
            "-s",                     # Silencieux
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        results = []
        if os.path.exists(tmp_path):
            with open(tmp_path) as f:
                data = json.loads(f.read())
            os.unlink(tmp_path)

            for result in data.get("results", []):
                results.append({
                    "path": f"/{result.get('input', {}).get('FUZZ', '')}",
                    "status_code": result.get("status", 0),
                    "content_length": result.get("length", 0),
                    "content_type": result.get("content-type", ""),
                    "words": result.get("words", 0),
                    "lines": result.get("lines", 0),
                })

        return jsonify({"url": url, "wordlist": wordlist, "results": results})

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout ffuf (120s)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/dns")
def dns():
    """Enumeration DNS avec subfinder + DNS bruteforce."""
    domain = request.args.get("domain", "")

    if not domain:
        return jsonify({"error": "Parametre 'domain' requis"}), 400

    subdomains = set()

    # 1. subfinder (sources OSINT)
    try:
        cmd = ["subfinder", "-d", domain, "-silent", "-timeout", "15"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        for line in proc.stdout.splitlines():
            if line.strip():
                subdomains.add(line.strip().lower())
    except Exception as e:
        print(f"subfinder erreur: {e}")

    # 2. DNS bruteforce (wordlist top 500)
    wordlist_path = os.path.join(WORDLISTS_DIR, "seclists", "dns-subdomains.txt")
    if os.path.exists(wordlist_path):
        prefixes = []
        with open(wordlist_path) as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    prefixes.append(line.strip())
                    if len(prefixes) >= 500:
                        break

        for prefix in prefixes:
            fqdn = f"{prefix}.{domain}"
            try:
                result = subprocess.run(
                    ["dig", "+short", fqdn], capture_output=True, text=True, timeout=2
                )
                if result.stdout.strip():
                    subdomains.add(fqdn)
            except Exception:
                pass

    # 3. Resoudre les IPs
    results = []
    for sub in sorted(subdomains):
        ip = "non resolu"
        try:
            result = subprocess.run(
                ["dig", "+short", sub], capture_output=True, text=True, timeout=2
            )
            ip = result.stdout.strip().split("\n")[0] if result.stdout.strip() else "non resolu"
        except Exception:
            pass
        results.append({"subdomain": sub, "ip": ip})

    return jsonify({"domain": domain, "subdomains": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
