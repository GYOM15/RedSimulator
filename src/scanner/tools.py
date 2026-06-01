"""Outils de scan pour l'agent ReAct.

Chaque outil est une fonction autonome utilisable par l'agent LangChain.
Les outils delegent le travail aux modules specialises
(http_utils, crawlers, form_parsing).
"""

import json
from pathlib import Path

from langchain_core.tools import tool

from src.infra.logging import get_logger
from src.infra.config import settings
from src.infra.decorators import timed, safe
from .http_utils import safe_request, parallel_requests, error_json
from .crawlers import build_paths_list
from .form_parsing import analyze_static_forms, analyze_dynamic_forms

logger = get_logger(__name__)


# Ports par defaut si l'agent ne precise pas
DEFAULT_PORTS = "21,22,80,443,3000,3306,5432,6379,8000,8080,8443,9200,27017"


@tool
@timed
def port_scan(target: str, ports: str = "") -> str:
    """Scanne les ports d'une cible pour decouvrir les services actifs.

    Tu peux appeler cet outil plusieurs fois avec des ports differents :
    - Sans preciser ports : scanne les ports les plus courants
    - Avec ports specifiques : scanne uniquement ceux-la
      Exemple : ports="27017,6379" pour verifier MongoDB et Redis

    Args:
        target: URL ou IP de la cible (ex: http://localhost:3000)
        ports: Ports a scanner, separes par des virgules (optionnel).
               Si vide, scanne les ports courants (web, DB, cache, etc.)

    Returns:
        JSON des ports ouverts avec service et version.
    """
    ports_to_scan = ports.strip() if ports.strip() else DEFAULT_PORTS
    logger.info("Scan de ports sur %s (%s)...", target, ports_to_scan)

    host = target.replace("http://", "").replace("https://", "").split(":")[0]

    # 1. Service nmap Docker
    results = _port_scan_docker(host, ports_to_scan)

    # 2. nmap local
    if results is None:
        results = _port_scan_nmap(host, ports_to_scan)

    # 3. Fallback socket
    if results is None:
        results = _port_scan_socket(host, ports_to_scan)

    # Construire un resume pour l'agent
    summary = _build_port_summary(results)
    return json.dumps({"ports": results, "summary": summary}, indent=2)


def _build_port_summary(ports: list) -> str:
    """Resume factuel des ports — sans jugement, l'agent decide."""
    if not ports:
        return "Aucun port ouvert detecte."

    lines = [f"{len(ports)} port(s) ouvert(s) :"]
    for p in ports:
        service = p.get("service", "unknown")
        version = p.get("version") or ""
        lines.append(f"  Port {p['port']}: {service} {version}".rstrip())

    return "\n".join(lines)


@safe(fallback=None)
def _port_scan_docker(host: str, ports: str) -> list | None:
    """Scan via le micro-service nmap Docker."""
    nmap_url = settings.recon_service_url
    resp, error = safe_request(f"{nmap_url}/scan?host={host}&ports={ports}", timeout=settings.request_timeout)
    if resp is None:
        logger.debug("Service nmap Docker non disponible")
        return None

    data = resp.json()
    if "error" in data:
        logger.warning("Service nmap erreur: %s", data['error'])
        return None

    results = data.get("results", [])
    logger.info("%d ports trouves (nmap Docker)", len(results))
    return results


@safe(fallback=None)
def _port_scan_nmap(host: str, ports: str) -> list | None:
    """Scan via nmap local."""
    import nmap
    nm = nmap.PortScanner()
    nm.scan(host, ports, arguments="-sV --version-intensity 2")

    results = []
    for proto in nm[host].all_protocols():
        for port in nm[host][proto].keys():
            state = nm[host][proto][port]
            if state["state"] == "open":
                results.append({
                    "port": port,
                    "service": state.get("name", "unknown"),
                    "version": f"{state.get('product', '')} {state.get('version', '')}".strip() or None,
                })

    logger.info("%d ports trouves (nmap local)", len(results))
    return results


def _port_scan_socket(host: str, ports: str) -> list:
    """Fallback : scan basique avec socket (parallele)."""
    import socket
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _check_port(port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None

    port_list = [int(p) for p in ports.split(",")]
    results = []

    with ThreadPoolExecutor(max_workers=len(port_list)) as executor:
        futures = {executor.submit(_check_port, p): p for p in port_list}
        for future in as_completed(futures):
            port = future.result()
            if port is not None:
                results.append({"port": port, "service": "unknown", "version": None})

    logger.info("%d ports trouves (fallback socket)", len(results))
    return results


def _analyze_cookies(resp) -> list:
    """Analyse les cookies pour les flags de securite."""
    cookies = []
    for cookie_header in resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else [resp.headers.get("Set-Cookie", "")]:
        if not cookie_header:
            continue

        name = cookie_header.split("=")[0].strip()
        lower = cookie_header.lower()

        issues = []
        if "secure" not in lower:
            issues.append("Secure manquant")
        if "httponly" not in lower:
            issues.append("HttpOnly manquant")
        if "samesite" not in lower:
            issues.append("SameSite manquant")

        cookie_info = {"name": name, "secure": "secure" in lower, "httponly": "httponly" in lower, "samesite": "samesite" in lower, "issues": issues}
        cookies.append(cookie_info)

        if issues:
            logger.debug("Cookie '%s' : %s", name, ', '.join(issues))
        else:
            logger.debug("Cookie '%s' : bien configure", name)

    return cookies


def _check_cors(target: str) -> dict:
    """Verifie la configuration CORS."""
    import requests

    cors_result = {"misconfigured": False, "allows_any_origin": False, "allows_credentials": False, "details": ""}

    try:
        # Envoyer une requete avec un Origin malveillant
        headers = {"Origin": "https://evil-attacker.com"}
        resp = requests.get(target, headers=headers, timeout=settings.request_timeout, allow_redirects=False)

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            cors_result["allows_any_origin"] = True
            cors_result["misconfigured"] = True
            cors_result["details"] = "Access-Control-Allow-Origin: * (tout le monde)"
            logger.debug("CORS: accepte toute origine (*)")
        elif acao == "https://evil-attacker.com":
            cors_result["allows_any_origin"] = True
            cors_result["misconfigured"] = True
            cors_result["details"] = "Reflete l'origine de l'attaquant"
            logger.debug("CORS: reflete l'origine malveillante")
        else:
            logger.debug("CORS: origine restreinte ou non configure")

        if acac.lower() == "true" and cors_result["allows_any_origin"]:
            cors_result["allows_credentials"] = True
            cors_result["misconfigured"] = True
            logger.debug("CORS: autorise les credentials avec origine ouverte")

    except Exception as e:
        cors_result["details"] = f"Verification echouee: {e}"

    return cors_result


def _calibrate_soft404(base_url: str) -> dict | None:
    """Calibration du soft-404 (technique ffuf/feroxbuster).

    Envoie des requetes vers des chemins aleatoires qui n'existent pas.
    La reponse recue = le comportement du serveur pour les pages inexistantes.
    On capture plusieurs metriques pour une detection robuste.

    Returns:
        Dict avec length, words, lines du soft-404, ou None si pas de soft-404.
    """
    import uuid

    # 3 chemins aleatoires pour confirmer le pattern
    calibration_paths = [
        f"/{uuid.uuid4().hex[:12]}",
        f"/{uuid.uuid4().hex[:8]}.html",
        f"/api/{uuid.uuid4().hex[:10]}",
    ]

    signatures = []
    for path in calibration_paths:
        resp, _ = safe_request(f"{base_url}{path}", timeout=3)
        if resp is None:
            continue

        sig = {
            "status": resp.status_code,
            "length": len(resp.text),
            "words": len(resp.text.split()),
            "lines": resp.text.count("\n"),
            "content_type": resp.headers.get("Content-Type", "").lower(),
        }
        signatures.append(sig)

    if not signatures:
        return None

    # Verifier que les reponses sont coherentes (meme pattern)
    lengths = [s["length"] for s in signatures]
    if max(lengths) - min(lengths) > 200:
        # Reponses trop differentes = pas de soft-404 coherent
        return None

    # Utiliser la mediane comme reference
    ref = signatures[len(signatures) // 2]
    logger.debug("Soft-404 calibre: %d bytes, %d words, status %d", ref['length'], ref['words'], ref['status'])
    return ref


def _is_soft404(resp, calibration: dict | None) -> bool:
    """Detecte si une reponse est un soft-404 (fausse page).

    Compare avec la calibration sur 3 metriques :
    - Taille du body (tolerance 5%)
    - Nombre de mots (tolerance 5%)
    - Content-Type identique
    """
    if calibration is None:
        return False

    # Ne filtrer que les 200 (les 401, 403 sont de vrais statuts)
    if resp.status_code != 200:
        return False

    content_type = resp.headers.get("Content-Type", "").lower()
    cal_ct = calibration["content_type"]

    # Content-Type different = reponse differente (ex: JSON vs HTML)
    if "text/html" in cal_ct and "text/html" not in content_type:
        return False
    if "application/json" in cal_ct and "application/json" not in content_type:
        return False

    # Taille similaire (tolerance 5%)
    body_len = len(resp.text)
    cal_len = calibration["length"]
    if cal_len == 0:
        return body_len == 0

    size_ratio = abs(body_len - cal_len) / cal_len
    if size_ratio < 0.05:
        return True

    # Nombre de mots similaire (tolerance 5%)
    words = len(resp.text.split())
    cal_words = calibration["words"]
    if cal_words > 0:
        words_ratio = abs(words - cal_words) / cal_words
        if words_ratio < 0.05 and size_ratio < 0.15:
            return True

    return False



# Patterns de parametres dans les URLs
PARAM_PATTERNS = [
    (r'\{(\w+)\}', "path_param"),     # /api/users/{id}
    (r':(\w+)', "path_param"),        # /api/users/:id
    (r'\?(.+)', "query_param"),       # /search?q=test
]


@tool
@timed
def endpoint_discovery(target: str) -> str:
    """Decouvre les endpoints accessibles sur la cible.

    Retourne un resume intelligent avec :
    - Liste complete des endpoints
    - Classification par risque (critiques, proteges, publics)
    - Detection des fichiers sensibles exposes
    - Extraction des parametres

    Args:
        target: URL de base de la cible (ex: http://localhost:3000)

    Returns:
        JSON avec les endpoints + un resume textuel pour analyse.
    """
    logger.info("Decouverte des endpoints sur %s...", target)

    all_paths = build_paths_list(target)
    base_url = target.rstrip("/")
    endpoints = []
    sensitive_findings = []

    # Calibration soft-404 (technique ffuf/feroxbuster)
    soft404 = _calibrate_soft404(base_url)

    # Requetes en parallele (10 threads)
    url_list = [(f"{base_url}{entry['path']}", entry["method"]) for entry in all_paths]
    path_map = {f"{base_url}{entry['path']}": entry["path"] for entry in all_paths}

    results = parallel_requests(url_list, timeout=settings.request_timeout, max_workers=settings.max_concurrent_requests)

    for url, method, resp in results:
        if resp is None:
            continue

        # Filtrer les soft-404 (fausses pages)
        if _is_soft404(resp, soft404):
            continue

        path = path_map.get(url, url.replace(base_url, ""))
        parameters = _extract_parameters(path, resp)

        ep = {
            "path": path,
            "method": method,
            "status_code": resp.status_code,
            "auth_required": resp.status_code == 401,
            "parameters": parameters,
        }
        endpoints.append(ep)
        logger.debug("  [+] %s %s -> %d", method, path, resp.status_code)

        if resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "").lower()
            is_page = "text/html" in content_type and len(resp.text) > 1000
            if not is_page:
                finding = _analyze_sensitive_content(path, resp)
                if finding:
                    sensitive_findings.append(finding)

    # Construire le resume intelligent
    summary = _build_discovery_summary(endpoints, sensitive_findings)

    logger.info("%d endpoints decouverts", len(endpoints))
    return json.dumps({
        "endpoints": endpoints,
        "sensitive_findings": sensitive_findings,
        "summary": summary,
    }, indent=2)


def _extract_parameters(path: str, resp) -> list:
    """Extrait les parametres depuis le path et le contenu."""
    import re
    params = []

    # Path params : /api/users/{id} ou /rest/basket/:id
    for pattern, param_type in PARAM_PATTERNS:
        for match in re.findall(pattern, path):
            if param_type == "query_param":
                for pair in match.split("&"):
                    name = pair.split("=")[0]
                    params.append(name)
            else:
                params.append(match)

    # Detecter les IDs numeriques dans le path : /rest/basket/1
    parts = path.rstrip("/").split("/")
    for i, part in enumerate(parts):
        if part.isdigit() and i > 0:
            params.append(f"{parts[i-1]}_id")

    # Si c'est du JSON, extraire les cles du body
    content_type = resp.headers.get("Content-Type", "")
    if "application/json" in content_type and resp.status_code == 200:
        try:
            body = resp.json()
            if isinstance(body, dict):
                # Cles du premier niveau
                for key in list(body.keys())[:10]:
                    if key not in ("status", "data", "message"):
                        params.append(key)
            elif isinstance(body, list) and body:
                # Cles du premier element
                if isinstance(body[0], dict):
                    for key in list(body[0].keys())[:10]:
                        params.append(key)
        except Exception:
            pass

    return list(set(params))


def _analyze_sensitive_content(path: str, resp) -> dict | None:
    """Analyse le contenu d'une reponse pour detecter des informations sensibles.

    Ne se base PAS sur le nom du fichier mais sur le CONTENU.
    Detecte : variables d'environnement, cles API, documentation API,
    code source, fichiers de config, dependances.
    """
    content = resp.text[:3000]
    content_lower = content.lower()

    # Pattern 1 : Variables d'environnement (KEY=VALUE)
    import re
    env_vars = re.findall(r'^([A-Z_]{3,})=(.+)$', content, re.MULTILINE)
    sensitive_vars = [k for k, v in env_vars if any(s in k.lower() for s in ("key", "secret", "password", "token", "database", "api"))]
    if sensitive_vars:
        return {"path": path, "details": f"Variables d'environnement exposees ({len(env_vars)} total, {len(sensitive_vars)} sensibles) : {', '.join(sensitive_vars[:5])}"}

    # Pattern 2 : Documentation API (OpenAPI/Swagger)
    try:
        data = resp.json()
        if isinstance(data, dict):
            if "paths" in data or "swagger" in data or "openapi" in data:
                paths = list(data.get("paths", {}).keys())
                return {"path": path, "details": f"Documentation API exposee avec {len(paths)} endpoints : {', '.join(paths[:8])}"}
            if "dependencies" in data:
                deps = list(data["dependencies"].keys())
                return {"path": path, "details": f"Manifest de dependances expose ({len(deps)}) : {', '.join(deps[:8])}"}
    except Exception:
        pass

    # Pattern 3 : Repertoire Git
    if "ref: refs/" in content or "[core]" in content:
        return {"path": path, "details": "Repertoire de controle de version expose (Git)"}

    # Pattern 4 : Cles ou tokens dans le contenu brut
    key_patterns = re.findall(r'(?:api[_-]?key|secret|token|password)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})', content_lower)
    if key_patterns:
        return {"path": path, "details": f"{len(key_patterns)} cle(s)/token(s) potentiellement exposes dans le contenu"}

    # Pattern 5 : Code source (PHP, Python, Java, etc.)
    if any(marker in content for marker in ("<?php", "#!/usr/bin", "import java.", "from django", "require('")):
        return {"path": path, "details": "Code source applicatif expose"}

    return None


def _build_discovery_summary(endpoints: list, sensitive_findings: list) -> str:
    """Resume factuel des endpoints — sans jugement, l'agent decide.

    Liste les faits objectifs pour que l'agent fasse sa propre analyse.
    """
    total = len(endpoints)
    by_status = {}
    for ep in endpoints:
        code = ep["status_code"]
        by_status.setdefault(code, []).append(ep)

    with_params = [ep for ep in endpoints if ep.get("parameters")]

    lines = [f"{total} endpoints decouverts."]

    # Repartition par status code
    for code in sorted(by_status.keys()):
        eps = by_status[code]
        lines.append(f"  HTTP {code} : {len(eps)} endpoints")

    # Lister TOUS les endpoints publics (200) avec leurs parametres
    if 200 in by_status:
        lines.append(f"\nEndpoints publics (200) :")
        for ep in by_status[200]:
            params = f" params={ep['parameters']}" if ep.get("parameters") else ""
            lines.append(f"  {ep['method']} {ep['path']}{params}")

    # Lister les endpoints proteges (401)
    if 401 in by_status:
        lines.append(f"\nEndpoints proteges (401) :")
        for ep in by_status[401]:
            lines.append(f"  {ep['method']} {ep['path']}")

    # Autres codes (400, 403, etc.)
    other_codes = [c for c in by_status if c not in (200, 401)]
    if other_codes:
        lines.append(f"\nAutres reponses :")
        for code in other_codes:
            for ep in by_status[code]:
                lines.append(f"  {ep['method']} {ep['path']} -> {code}")

    # Fichiers sensibles — faits bruts
    if sensitive_findings:
        lines.append(f"\nFichiers sensibles exposes ({len(sensitive_findings)}) :")
        for f in sensitive_findings:
            lines.append(f"  {f['path']} : {f['details']}")

    return "\n".join(lines)


STANDARD_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


@tool
@timed
def header_checker(target: str, extra_headers: str = "") -> str:
    """Analyse les headers de securite HTTP de la cible.

    Verifie les headers de securite standards, les cookies, CORS,
    et les fuites d'information serveur. Tu peux ajouter des headers
    supplementaires a verifier si tu suspectes quelque chose.

    Args:
        target: URL de la cible
        extra_headers: Headers supplementaires a verifier (separes par des virgules).
                       Exemple: "X-Api-Key,Authorization" si tu suspectes une fuite.

    Returns:
        JSON avec headers manquants, cookies, CORS et infos exposees.
    """
    logger.info("Analyse des headers de securite sur %s...", target)

    resp, error = safe_request(target)
    if resp is None:
        return error_json(error)

    # 1. Headers de securite manquants
    security_headers = list(STANDARD_SECURITY_HEADERS)
    if extra_headers.strip():
        security_headers.extend(h.strip() for h in extra_headers.split(",") if h.strip())

    missing = []
    for header in security_headers:
        if header.lower() not in [h.lower() for h in resp.headers]:
            missing.append(header)
            logger.debug("Header manquant: %s", header)
        else:
            logger.debug("Header present: %s", header)

    # 2. Fuite d'information serveur
    server_info = resp.headers.get("Server", "")
    powered_by = resp.headers.get("X-Powered-By", "")
    server_leaked = bool(server_info or powered_by)

    if server_info:
        logger.debug("Server header expose: %s", server_info)
    if powered_by:
        logger.debug("X-Powered-By expose: %s", powered_by)

    # 3. Analyse des cookies
    cookies = _analyze_cookies(resp)

    # 4. Verification CORS
    cors = _check_cors(target)

    result = {
        "missing_security_headers": missing,
        "server_info_leaked": server_leaked,
        "server": server_info,
        "powered_by": powered_by,
        "cookies": cookies,
        "cors": cors,
    }

    logger.info("%d headers de securite manquants", len(missing))
    return json.dumps(result, indent=2)


@tool
@timed
def form_analyzer(target: str, endpoint: str) -> str:
    """Analyse les formulaires d'un endpoint (statique + dynamique).

    Tente d'abord une analyse statique (BeautifulSoup), puis
    une analyse dynamique (Playwright) si rien n'est trouve.

    Args:
        target: URL de base de la cible
        endpoint: Chemin de l'endpoint a analyser

    Returns:
        JSON des formulaires trouves avec leurs champs.
    """
    logger.info("Analyse des formulaires sur %s%s...", target, endpoint)

    url = f"{target.rstrip('/')}{endpoint}"

    forms_info = analyze_static_forms(url)

    if not forms_info:
        forms_info = analyze_dynamic_forms(url)

    logger.info("%d formulaires trouves sur %s", len(forms_info), endpoint)
    return json.dumps(forms_info, indent=2)


@tool
@timed
def probe_endpoint(target: str, path: str, method: str = "GET", body: str = "") -> str:
    """Teste un endpoint specifique avec une methode et un body personnalise.

    Utilise cet outil pour approfondir un endpoint interessant :
    tester differentes methodes (POST, PUT, DELETE), envoyer un body,
    ou verifier un comportement specifique.

    Args:
        target: URL de base (ex: http://localhost:3000)
        path: Chemin de l'endpoint (ex: /api/Users)
        method: Methode HTTP (GET, POST, PUT, DELETE)
        body: Corps JSON de la requete (optionnel)

    Returns:
        JSON avec status, headers et extrait du body de la reponse.
    """
    url = f"{target.rstrip('/')}{path}"
    logger.info("Probe %s %s...", method, url)

    json_body = None
    if body:
        try:
            import json as json_mod
            json_body = json_mod.loads(body)
        except Exception:
            json_body = {}

    resp, error = safe_request(url, method=method, json_body=json_body)
    if resp is None:
        return error_json(error)

    # Extraire les infos utiles
    body_preview = resp.text[:500] if resp.text else ""
    resp_headers = dict(resp.headers)

    result = {
        "url": url,
        "method": method,
        "status_code": resp.status_code,
        "content_type": resp.headers.get("Content-Type", ""),
        "body_preview": body_preview,
        "headers": {k: v for k, v in resp_headers.items() if k.lower() in (
            "server", "x-powered-by", "content-type", "set-cookie",
            "access-control-allow-origin", "www-authenticate", "location",
        )},
    }

    logger.debug("  [+] %s %s -> %d", method, path, resp.status_code)
    return json.dumps(result, indent=2)


@tool
@timed
def tech_detector(target: str) -> str:
    """Detecte les technologies et versions utilisees par la cible.

    Analyse les headers HTTP, le HTML, les fichiers JS et les endpoints
    connus (package.json, version API) pour identifier les frameworks,
    serveurs, bases de donnees et leurs versions.

    Args:
        target: URL de la cible

    Returns:
        JSON avec la liste des technologies detectees.
    """
    from .tech_detector import detect_technologies as _detect
    techs = _detect(target)
    return json.dumps({"technologies": techs}, indent=2)


@tool
@timed
def directory_bruteforce(target: str, category: str = "common") -> str:
    """Teste une liste de chemins courants pour decouvrir des ressources cachees.

    Utilise ffuf si disponible (rapide, filtrage soft-404 natif),
    sinon fallback Python avec calibration soft-404.

    Categories de wordlists (custom) :
    - "common" : pages d'admin, login, config
    - "sensitive" : .env, .git, backups, logs, credentials
    - "nodejs" : fichiers specifiques Node.js/Express
    - "backup" : archives, dumps SQL, fichiers .old/.bak

    Categories SecLists (pro, milliers de chemins) :
    - "seclists/web-common" : 4700 chemins courants (SecLists common.txt)
    - "seclists/web-directories" : 30000 repertoires (raft-medium)
    - "seclists/web-files" : 17000 fichiers (raft-medium)
    - "seclists/api-endpoints" : 285 endpoints API courants

    Tu peux appeler cet outil plusieurs fois avec des categories differentes.
    Pour un scan rapide, utilise "common" ou "sensitive".
    Pour un scan approfondi, utilise "seclists/web-common".

    Args:
        target: URL de base de la cible
        category: Categorie de wordlist

    Returns:
        JSON avec les chemins trouves (status 200/401/403) et l'analyse du contenu sensible.
    """
    logger.info("Bruteforce [%s] sur %s...", category, target)

    wordlist_path = Path(__file__).parent.parent.parent / "data" / "wordlists" / f"{category}.txt"
    if not wordlist_path.exists():
        available = [f.stem for f in wordlist_path.parent.glob("*.txt")]
        return error_json(f"Categorie '{category}' inconnue. Disponibles : {', '.join(available)}")

    # Essayer ffuf d'abord
    ffuf_result = _bruteforce_ffuf(target, str(wordlist_path))
    if ffuf_result is not None:
        found, sensitive = ffuf_result
    else:
        found, sensitive = _bruteforce_python(target, wordlist_path)

    summary = f"{len(found)} chemins trouves (categorie: {category})."
    if sensitive:
        summary += f"\n{len(sensitive)} contenu(s) sensible(s) detecte(s) :"
        for s in sensitive:
            summary += f"\n  {s['path']} : {s['details']}"

    logger.info("%d chemins trouves [%s]", len(found), category)
    return json.dumps({"found": found, "sensitive": sensitive, "summary": summary}, indent=2)


def _bruteforce_ffuf(target: str, wordlist_path: str) -> tuple[list, list] | None:
    """Bruteforce avec ffuf (Docker ou local).

    Essaie d'abord le service Docker recon-tools, sinon ffuf local.

    Returns:
        (found, sensitive) ou None si ffuf non disponible.
    """
    base_url = target.rstrip("/")

    # Determiner la categorie depuis le chemin de la wordlist
    wl_name = Path(wordlist_path).stem
    wl_parent = Path(wordlist_path).parent.name
    category = f"{wl_parent}/{wl_name}" if wl_parent != "wordlists" else wl_name

    # 1. Service Docker recon-tools
    recon_url = settings.recon_service_url
    try:
        resp, error = safe_request(f"{recon_url}/bruteforce?url={base_url}&wordlist={category}", timeout=60)
        if resp and resp.status_code == 200:
            data = resp.json()
            found = data.get("results", [])
            logger.debug("ffuf Docker: %d resultats", len(found))

            # Analyser le contenu sensible
            sensitive = []
            for entry in found:
                if entry.get("status_code") == 200:
                    ct = entry.get("content_type", "").lower()
                    length = entry.get("content_length", 0)
                    is_page = "text/html" in ct and length > 1000
                    if not is_page:
                        probe_resp, _ = safe_request(f"{base_url}{entry['path']}", timeout=3)
                        if probe_resp:
                            finding = _analyze_sensitive_content(entry["path"], probe_resp)
                            if finding:
                                sensitive.append(finding)

            return found, sensitive
    except Exception:
        pass

    # 2. ffuf local
    import os
    import shutil
    import subprocess
    import tempfile

    ffuf_bin = shutil.which("ffuf")
    if not ffuf_bin:
        logger.debug("ffuf non disponible (ni Docker ni local) — fallback Python")
        return None

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        cmd = [
            ffuf_bin,
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist_path,
            "-o", tmp_path,
            "-of", "json",
            "-ac",
            "-t", "10",
            "-timeout", "3",
            "-mc", "200,201,301,302,401,403",
            "-s",
        ]

        logger.debug("ffuf local: %s...", ' '.join(cmd[:6]))
        subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if not os.path.exists(tmp_path):
            return None

        with open(tmp_path) as f:
            data = json.loads(f.read())
        os.unlink(tmp_path)

        found = []
        sensitive = []

        for result in data.get("results", []):
            path = f"/{result.get('input', {}).get('FUZZ', '')}"
            entry = {
                "path": path,
                "status_code": result.get("status", 0),
                "content_type": result.get("content-type", ""),
                "content_length": result.get("length", 0),
            }
            found.append(entry)
            logger.debug("  [+] %s -> %d (%d bytes) [ffuf]", path, entry['status_code'], entry['content_length'])

            if entry["status_code"] == 200:
                is_page = "text/html" in entry["content_type"].lower() and entry["content_length"] > 1000
                if not is_page:
                    probe_resp, _ = safe_request(f"{base_url}{path}", timeout=3)
                    if probe_resp:
                        finding = _analyze_sensitive_content(path, probe_resp)
                        if finding:
                            sensitive.append(finding)

        logger.debug("ffuf local: %d resultats", len(found))
        return found, sensitive

    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("ffuf echoue: %s", e)
        return None


def _bruteforce_python(target: str, wordlist_path: Path) -> tuple[list, list]:
    """Fallback Python : requetes paralleles + calibration soft-404."""
    paths = [line.strip() for line in wordlist_path.read_text().splitlines()
             if line.strip() and not line.startswith("#")]
    logger.debug("Fallback Python: %d chemins a tester", len(paths))

    base_url = target.rstrip("/")
    found = []
    sensitive = []

    # Calibration soft-404
    soft404 = _calibrate_soft404(base_url)

    url_list = [(f"{base_url}/{path}", "GET") for path in paths]
    path_map = {f"{base_url}/{path}": f"/{path}" for path in paths}

    results = parallel_requests(url_list, timeout=settings.request_timeout, max_workers=settings.max_concurrent_requests)

    for url, method, resp in results:
        if resp is None:
            continue
        if resp.status_code in (404, 500, 502, 503):
            continue
        if _is_soft404(resp, soft404):
            continue

        path = path_map.get(url, url.replace(base_url, ""))
        entry = {
            "path": path,
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "content_length": len(resp.text),
        }
        found.append(entry)
        logger.debug("  [+] %s -> %d (%d bytes)", path, resp.status_code, len(resp.text))

        if resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "").lower()
            is_page = "text/html" in content_type and len(resp.text) > 1000
            if not is_page:
                finding = _analyze_sensitive_content(path, resp)
                if finding:
                    sensitive.append(finding)

    return found, sensitive


@tool
@timed
def dns_enum(target: str) -> str:
    """Enumere les sous-domaines d'une cible pour decouvrir la surface d'attaque.

    Utilise subfinder si disponible, sinon fallback via crt.sh (Certificate
    Transparency logs) et DNS bruteforce avec les wordlists SecLists.

    IMPORTANT : cet outil ne fonctionne que sur des domaines reels (example.com),
    PAS sur localhost ou des IPs. Si la cible est localhost ou une IP, ne l'appelle pas.

    Args:
        target: Domaine a enumerer (ex: example.com). PAS une URL complete.

    Returns:
        JSON avec les sous-domaines decouverts et leurs IPs.
    """
    import re
    from urllib.parse import urlparse

    # Extraire le domaine de l'URL
    domain = target.strip()
    if "://" in domain:
        domain = urlparse(domain).hostname or domain
    domain = domain.split(":")[0]  # Retirer le port

    # Ne pas enumerer localhost/IPs
    if domain in ("localhost", "127.0.0.1") or re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        return json.dumps({"subdomains": [], "summary": "Enumeration DNS non applicable sur localhost/IP."})

    logger.info("Enumeration DNS sur %s...", domain)

    # 1. Service Docker recon-tools
    recon_url = settings.recon_service_url
    try:
        resp, _ = safe_request(f"{recon_url}/dns?domain={domain}", timeout=30)
        if resp and resp.status_code == 200:
            data = resp.json()
            results = data.get("subdomains", [])
            logger.debug("Docker recon-tools: %d sous-domaines", len(results))

            summary = f"{len(results)} sous-domaine(s) decouvert(s) pour {domain}."
            if results:
                summary += "\n" + "\n".join(f"  {r['subdomain']} -> {r['ip']}" for r in results[:20])
            logger.info("%d sous-domaines trouves", len(results))
            return json.dumps({"subdomains": results, "summary": summary}, indent=2)
    except Exception:
        pass

    # 2. Fallback local : subfinder
    subdomains = _dns_subfinder(domain)

    # 3. Fallback : crt.sh + DNS bruteforce
    if subdomains is None:
        subdomains = set()
        crt_results = _dns_crtsh(domain)
        subdomains.update(crt_results)
        brute_results = _dns_bruteforce(domain)
        subdomains.update(brute_results)

    # 4. Resoudre les IPs
    results = _resolve_subdomains(list(subdomains))

    summary = f"{len(results)} sous-domaine(s) decouvert(s) pour {domain}."
    if results:
        summary += "\n" + "\n".join(f"  {r['subdomain']} -> {r['ip']}" for r in results[:20])
        if len(results) > 20:
            summary += f"\n  ... et {len(results) - 20} autres"

    logger.info("%d sous-domaines trouves", len(results))
    return json.dumps({"subdomains": results, "summary": summary}, indent=2)


def _dns_subfinder(domain: str) -> set | None:
    """Enumeration avec subfinder (rapide, utilise des sources OSINT)."""
    import shutil
    import subprocess

    subfinder_bin = shutil.which("subfinder")
    if not subfinder_bin:
        logger.debug("subfinder non disponible — fallback crt.sh + bruteforce")
        return None

    try:
        cmd = [subfinder_bin, "-d", domain, "-silent", "-timeout", "15"]
        logger.debug("subfinder: %s...", domain)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        subs = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
        logger.debug("subfinder: %d sous-domaines", len(subs))
        return subs
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning("subfinder echoue: %s", e)
        return None


@safe(fallback=set())
def _dns_crtsh(domain: str) -> set:
    """Enumeration via Certificate Transparency (crt.sh)."""
    subdomains = set()
    resp, _ = safe_request(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
    if resp and resp.status_code == 200:
        data = resp.json()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    # Ignorer les wildcards
                    if not sub.startswith("*"):
                        subdomains.add(sub)
        logger.debug("crt.sh: %d sous-domaines", len(subdomains))

    return subdomains


def _dns_bruteforce(domain: str) -> set:
    """Bruteforce DNS avec la wordlist SecLists."""
    import socket

    wordlist_path = Path(__file__).parent.parent.parent / "data" / "wordlists" / "seclists" / "dns-subdomains.txt"
    if not wordlist_path.exists():
        logger.debug("Wordlist DNS non disponible (lancer scripts/setup_wordlists.sh)")
        return set()

    # Limiter a 500 pour ne pas etre trop lent
    prefixes = [line.strip() for line in wordlist_path.read_text().splitlines()
                if line.strip() and not line.startswith("#")][:500]

    logger.debug("DNS bruteforce: %d prefixes a tester...", len(prefixes))
    subdomains = set()

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _resolve(prefix: str):
        fqdn = f"{prefix}.{domain}"
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM)
            return fqdn
        except socket.gaierror:
            return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_resolve, p): p for p in prefixes}
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomains.add(result)

    logger.debug("DNS bruteforce: %d sous-domaines resolus", len(subdomains))
    return subdomains


def _resolve_subdomains(subdomains: list) -> list:
    """Resout les IPs de chaque sous-domaine."""
    import socket
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = []

    def _resolve(sub: str):
        try:
            ip = socket.gethostbyname(sub)
            return {"subdomain": sub, "ip": ip}
        except socket.gaierror:
            return {"subdomain": sub, "ip": "non resolu"}

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_resolve, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda r: r["subdomain"])


if __name__ == "__main__":
    from src.infra.logging import setup_logging
    setup_logging(level=settings.log_level, fmt=settings.log_format)

    logger.info("=== Test des outils de scan ===")

    target = "http://localhost:3000"

    logger.info("--- Port Scan ---")
    logger.info(port_scan.invoke({"target": target}))

    logger.info("--- Endpoint Discovery ---")
    logger.info(endpoint_discovery.invoke({"target": target}))

    logger.info("--- Header Checker ---")
    logger.info(header_checker.invoke({"target": target}))

    logger.info("--- Form Analyzer (page login) ---")
    logger.info(form_analyzer.invoke({"target": target, "endpoint": "/#/login"}))

    logger.info("--- Tech Detector ---")
    logger.info(tech_detector.invoke({"target": target}))

    logger.info("--- Directory Bruteforce ---")
    logger.info(directory_bruteforce.invoke({"target": target, "category": "sensitive"}))

    logger.info("--- Probe Endpoint ---")
    logger.info(probe_endpoint.invoke({"target": target, "path": "/rest/user/login", "method": "POST", "body": "{}"}))
