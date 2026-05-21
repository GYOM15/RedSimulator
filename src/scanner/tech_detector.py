"""Detection des technologies et versions utilisees par la cible.

Analyse les headers HTTP, le contenu HTML, les fichiers JS
et les endpoints connus pour identifier les frameworks,
serveurs, bases de donnees et leurs versions.
"""

import re

from bs4 import BeautifulSoup

from .http_utils import safe_request, parallel_requests


def detect_technologies(target: str) -> list[str]:
    """Detecte les technologies utilisees par la cible.

    Combine 4 sources : headers HTTP, contenu HTML, fichiers JS, endpoints connus.

    Args:
        target: URL de la cible

    Returns:
        Liste de technologies detectees (avec versions quand possible).
    """
    print(f"[SCANNER] Detection des technologies sur {target}...")

    resp, error = safe_request(target)
    if resp is None:
        return []

    techs = set()
    techs.update(_detect_from_headers(resp.headers))
    techs.update(_detect_from_html(resp.text))
    techs.update(_detect_from_js(resp.text, target))
    techs.update(_detect_from_endpoints(target))

    result = sorted(techs)
    print(f"[SCANNER] {len(result)} technologies detectees: {result}")
    return result


def _detect_from_headers(headers) -> set:
    """Detecte les technologies depuis les headers HTTP."""
    techs = set()

    # Server header (avec version)
    server = headers.get("Server", "")
    if server:
        techs.add(f"Server: {server}")
    server_lower = server.lower()
    if "express" in server_lower:
        techs.add("Express")
    if "nginx" in server_lower:
        techs.add("Nginx")
    if "apache" in server_lower:
        techs.add("Apache")

    # X-Powered-By (avec version)
    powered = headers.get("X-Powered-By", "")
    if powered:
        techs.add(f"X-Powered-By: {powered}")
    powered_lower = powered.lower()
    if "express" in powered_lower:
        techs.update(["Node.js", "Express"])
    if "php" in powered_lower:
        techs.add(f"PHP ({powered})" if powered else "PHP")
    if "asp.net" in powered_lower:
        techs.add("ASP.NET")

    # Cookies
    set_cookie = headers.get("Set-Cookie", "").lower()
    if "connect.sid" in set_cookie:
        techs.add("Express (session)")
    if "phpsessid" in set_cookie:
        techs.add("PHP")
    if "jsessionid" in set_cookie:
        techs.add("Java")
    if "csrftoken" in set_cookie:
        techs.add("Django")

    return techs


def _detect_from_html(html: str) -> set:
    """Detecte les technologies et versions depuis le contenu HTML."""
    techs = set()
    soup = BeautifulSoup(html, "html.parser")
    html_lower = html.lower()

    # Angular avec version
    ng_version = re.search(r'ng-version="([^"]+)"', html)
    if ng_version:
        techs.add(f"Angular {ng_version.group(1)}")
    elif soup.find(attrs={"ng-app": True}) or "angular" in html_lower:
        techs.add("Angular")

    # React
    if "react" in html_lower or "__next" in html_lower or "data-reactroot" in html_lower:
        techs.add("React")

    # Vue.js
    if "vue" in html_lower or soup.find(attrs={"v-app": True}):
        techs.add("Vue.js")

    # jQuery avec version
    jq_match = re.search(r'jquery[.-](\d+\.\d+\.\d+)', html_lower)
    if jq_match:
        techs.add(f"jQuery {jq_match.group(1)}")
    elif "jquery" in html_lower:
        techs.add("jQuery")

    # Bootstrap avec version
    bs_match = re.search(r'bootstrap[.-](\d+\.\d+\.\d+)', html_lower)
    if bs_match:
        techs.add(f"Bootstrap {bs_match.group(1)}")
    elif "bootstrap" in html_lower:
        techs.add("Bootstrap")

    # Angular Material
    if "mat-toolbar" in html_lower or "mat-sidenav" in html_lower:
        techs.add("Angular Material")

    return techs


def _detect_from_js(html: str, target: str) -> set:
    """Detecte les technologies et versions depuis les fichiers JS."""
    techs = set()
    soup = BeautifulSoup(html, "html.parser")
    base_url = target.rstrip("/")

    for tag in soup.find_all("script", src=True):
        src = tag["src"].lower()
        if "angular" in src or "polyfills" in src:
            techs.add("Angular")
        if "react" in src:
            techs.add("React")
        if "vue" in src:
            techs.add("Vue.js")
        if "socket.io" in src:
            techs.add("Socket.IO")

    # Prioritiser les JS importants (main, vendor, polyfills) — max 5
    js_tags = soup.find_all("script", src=True)
    priority_keywords = ("main", "vendor", "polyfill", "runtime", "app")
    prioritized = sorted(js_tags, key=lambda t: (
        0 if any(k in t["src"].lower() for k in priority_keywords) else 1
    ))[:5]

    # Construire les URLs
    js_urls = []
    for tag in prioritized:
        src = tag["src"]
        if src.startswith("http"):
            js_urls.append(src)
        elif src.startswith("/"):
            js_urls.append(f"{base_url}{src}")
        else:
            js_urls.append(f"{base_url}/{src}")

    print(f"  [*] Tech detector: analyse de {len(js_urls)}/{len(js_tags)} fichiers JS")

    # Telecharger en parallele (timeout court)
    results = parallel_requests([(url, "GET") for url in js_urls], timeout=3, max_workers=5)

    for url, method, resp in results:
        if not resp:
            continue

        js = resp.text
        js_lower = js.lower()

        # Backend technologies
        if "sqlite" in js_lower or "sequelize" in js_lower:
            techs.add("SQLite")
        if "mongodb" in js_lower or "mongoose" in js_lower:
            techs.add("MongoDB")
        if "jsonwebtoken" in js_lower or "jwt" in js_lower:
            techs.add("JWT")
        if "socket.io" in js_lower:
            techs.add("Socket.IO")
        if "express" in js_lower:
            techs.update(["Node.js", "Express"])
        if "helmet" in js_lower:
            techs.add("Helmet.js")
        if "passport" in js_lower:
            techs.add("Passport.js")

        for name, pattern in [
            ("Express", r'express["\s:]+(\d+\.\d+\.\d+)'),
            ("Angular", r'angular[/\-]core["\s:@]+(\d+\.\d+\.\d+)'),
            ("Node.js", r'node["\s:]+v?(\d+\.\d+\.\d+)'),
        ]:
            match = re.search(pattern, js_lower)
            if match:
                techs.discard(name)
                techs.add(f"{name} {match.group(1)}")

    return techs


def _detect_from_endpoints(target: str) -> set:
    """Detecte les technologies en interrogeant des endpoints connus."""
    techs = set()
    base = target.rstrip("/")

    # package.json expose (fuite d'info commune)
    resp, _ = safe_request(f"{base}/package.json")
    if resp and resp.status_code == 200:
        try:
            pkg = resp.json()
            techs.add("package.json expose")
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            for name, version in deps.items():
                clean_v = version.lstrip("^~>=<")
                if name == "express":
                    techs.add(f"Express {clean_v}")
                elif name == "@angular/core":
                    techs.add(f"Angular {clean_v}")
                elif name == "sequelize":
                    techs.add(f"Sequelize {clean_v}")
                elif name == "jsonwebtoken":
                    techs.add(f"JWT ({clean_v})")
                elif name == "sqlite3":
                    techs.add(f"SQLite3 {clean_v}")
            print(f"  [!] package.json expose avec {len(deps)} dependances")
        except Exception:
            pass

    # /rest/admin/application-version (specifique Juice Shop mais pattern courant)
    resp, _ = safe_request(f"{base}/rest/admin/application-version")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            version = data.get("version", "")
            if version:
                techs.add(f"Application {version}")
                print(f"  [+] Version application: {version}")
        except Exception:
            pass

    return techs
