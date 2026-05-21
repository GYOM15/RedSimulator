"""Micro-service nmap.

Expose nmap via une API REST pour que le scanner Python
puisse l'appeler sans avoir nmap installe localement.

Endpoints:
    GET /scan?host=<host>&ports=<ports>  — Scan TCP avec detection de services
    GET /health                          — Health check
"""

import json
from flask import Flask, request, jsonify
import nmap

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "nmap_version": nmap.PortScanner().nmap_version_number()})


@app.route("/scan")
def scan():
    """Scan TCP avec detection de services.

    Params:
        host: IP ou hostname (ex: juiceshop, localhost)
        ports: Ports a scanner (ex: 80,443,3000)
    """
    host = request.args.get("host", "")
    ports = request.args.get("ports", "80,443,3000,8080,8443")

    if not host:
        return jsonify({"error": "host requis"}), 400

    try:
        nm = nmap.PortScanner()
        nm.scan(host, ports, arguments="-sV --version-intensity 2 -T4")

        results = []
        for h in nm.all_hosts():
            for proto in nm[h].all_protocols():
                for port in nm[h][proto].keys():
                    state = nm[h][proto][port]
                    if state["state"] == "open":
                        version = f"{state.get('product', '')} {state.get('version', '')}".strip()
                        results.append({
                            "port": port,
                            "service": state.get("name", "unknown"),
                            "version": version or None,
                            "state": state["state"],
                        })

        return jsonify({"host": host, "ports_scanned": ports, "results": results})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
