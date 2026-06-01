"""Crawlers pour la decouverte de chemins et endpoints.

Combine trois strategies de decouverte :
- Statique : liens HTML (balises <a>, <link>, <script>)
- Analyse JS : extraction de routes depuis les bundles JavaScript
- Dynamique : rendu Playwright pour les SPA (Angular, React, etc.)
"""

import json
import re
from pathlib import Path

from bs4 import BeautifulSoup

from src.infra.logging import get_logger
from .http_utils import safe_request

logger = get_logger(__name__)


def load_common_paths() -> list[dict]:
    """Charge les chemins generiques depuis le fichier de config."""
    config_path = Path(__file__).parent.parent.parent / "data" / "config" / "common_paths.json"
    try:
        return json.loads(config_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Impossible de charger %s: %s", config_path, e)
        return []


def crawl_html_links(target: str) -> set:
    """Extrait les liens internes depuis le HTML statique."""
    resp, error = safe_request(target)
    if resp is None:
        return set()

    soup = BeautifulSoup(resp.text, "html.parser")
    links = set()

    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        if href.startswith("/"):
            links.add(href.split("?")[0])

    for tag in soup.find_all("link", href=True):
        href = tag["href"]
        if href.startswith("/"):
            links.add(href)

    return links


def crawl_js_routes(target: str) -> list[dict]:
    """Analyse statique des fichiers JS pour extraire les routes API.

    Returns:
        Liste de dicts {"path": ..., "method": ...}
    """
    resp, error = safe_request(target)
    if resp is None:
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    js_urls = _extract_js_urls(soup, target)
    logger.debug("%d fichiers JS trouves", len(js_urls))

    seen = set()
    routes = []
    for js_url in js_urls:
        for entry in _extract_routes_from_js(js_url):
            if entry["path"] not in seen:
                seen.add(entry["path"])
                routes.append(entry)

    logger.debug("%d routes extraites des fichiers JS", len(routes))
    return routes


def crawl_dynamic(target: str) -> set:
    """Utilise Playwright pour rendre la SPA et extraire les liens.

    Reutilise le navigateur singleton pour eviter de lancer
    plusieurs processus Chromium.

    Returns:
        Set de chemins decouverts.
    """
    from .browser import new_page, close_page

    links = set()
    page = new_page(target)
    if page is None:
        return links

    try:
        # Liens classiques
        for a in page.query_selector_all("a[href]"):
            href = a.get_attribute("href") or ""
            if href.startswith("/"):
                links.add(href.split("?")[0])

        # Routes Angular (hash routes /#/...)
        angular_routes = page.evaluate("""() => {
            const links = document.querySelectorAll('a[href*="#/"]');
            return Array.from(links).map(a => a.getAttribute('href')).filter(Boolean);
        }""")
        for route in angular_routes:
            links.add(route.split("?")[0])

        # routerLink Angular
        router_links = page.evaluate("""() => {
            const links = document.querySelectorAll('[routerlink]');
            return Array.from(links).map(el => el.getAttribute('routerlink')).filter(Boolean);
        }""")
        for route in router_links:
            if not route.startswith("/"):
                route = f"/{route}"
            links.add(route)

        # Requetes reseau pour decouvrir les API
        api_calls = page.evaluate("""() => {
            return performance.getEntriesByType('resource')
                .map(e => new URL(e.name).pathname)
                .filter(p => p.startsWith('/api/') || p.startsWith('/rest/'));
        }""")
        for path in api_calls:
            links.add(path)

    except Exception as e:
        logger.warning("Crawl dynamique echoue: %s", e)
    finally:
        close_page(page)

    logger.debug("Playwright: %d liens dynamiques", len(links))
    return links


def build_paths_list(target: str) -> list[dict]:
    """Construit la liste de chemins a tester (config + HTML + JS + Playwright conditionnel)."""
    config_paths = load_common_paths()
    html_links = crawl_html_links(target)
    js_routes = crawl_js_routes(target)

    # Playwright seulement si HTML+JS trouvent peu de routes (SPA)
    if len(html_links) + len(js_routes) < 10:
        logger.debug("Peu de routes statiques — lancement Playwright")
        dynamic_links = crawl_dynamic(target)
    else:
        logger.debug("%d routes statiques — Playwright non necessaire", len(html_links) + len(js_routes))
        dynamic_links = set()

    seen = set()
    all_paths = []

    # 1. Config (chemins generiques)
    for entry in config_paths:
        if entry["path"] not in seen:
            seen.add(entry["path"])
            all_paths.append(entry)

    # 2. Routes JS (avec methode HTTP detectee)
    for entry in js_routes:
        if entry["path"] not in seen:
            seen.add(entry["path"])
            all_paths.append(entry)

    # 3. Liens HTML + Playwright (GET par defaut)
    for path in html_links | dynamic_links:
        if path not in seen:
            seen.add(path)
            all_paths.append({"path": path, "method": "GET"})

    logger.debug("Total: %d config + %d HTML + %d JS + %d dynamiques = %d uniques", len(config_paths), len(html_links), len(js_routes), len(dynamic_links), len(all_paths))
    return all_paths


# ---------- Helpers prives ----------

def _extract_js_urls(soup: BeautifulSoup, target: str) -> list[str]:
    """Extrait les URLs des fichiers JS depuis le HTML."""
    base_url = target.rstrip("/")
    js_urls = []

    # Scripts <script src="...">
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("http"):
            js_urls.append(src)
        elif src.startswith("/"):
            js_urls.append(f"{base_url}{src}")
        else:
            # Chemin relatif (ex: "main.js" au lieu de "/main.js")
            js_urls.append(f"{base_url}/{src}")

    # Chunks JS dans les <link> (Angular/React preload)
    for tag in soup.find_all("link", href=True):
        href = tag["href"]
        if href.endswith(".js"):
            if href.startswith("http"):
                js_urls.append(href)
            elif href.startswith("/"):
                js_urls.append(f"{base_url}{href}")
            else:
                js_urls.append(f"{base_url}/{href}")

    return js_urls


def _extract_routes_from_js(js_url: str) -> list[dict]:
    """Extrait les routes API depuis le contenu d'un fichier JS avec leur methode HTTP.

    Returns:
        Liste de dicts {"path": ..., "method": ...}
    """
    js_resp, error = safe_request(js_url, timeout=5)
    if js_resp is None:
        return []

    content = js_resp.text
    static_extensions = (".js", ".css", ".map", ".png", ".jpg", ".svg", ".ico", ".woff", ".ttf")

    # Detecter les routes avec leur methode HTTP
    # Patterns: http.post("/api/Users"), fetch("/graphql", {method: "POST"})
    method_patterns = [
        (r'\.post\s*\(\s*["\'](/[a-zA-Z0-9_/\-\.]+)["\']', "POST"),
        (r'\.put\s*\(\s*["\'](/[a-zA-Z0-9_/\-\.]+)["\']', "PUT"),
        (r'\.delete\s*\(\s*["\'](/[a-zA-Z0-9_/\-\.]+)["\']', "DELETE"),
        (r'\.get\s*\(\s*["\'](/[a-zA-Z0-9_/\-\.]+)["\']', "GET"),
        (r'\.patch\s*\(\s*["\'](/[a-zA-Z0-9_/\-\.]+)["\']', "PATCH"),
    ]

    # Routes sans methode (fallback GET) — patterns larges
    generic_patterns = [
        r'["\'](/api/[a-zA-Z0-9_/\-\.]+)["\']',
        r'["\'](/rest/[a-zA-Z0-9_/\-\.]+)["\']',
        r'["\'](/graphql[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/webhook[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/auth[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/oauth[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/admin[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/internal[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/socket\.io[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/metrics[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/health[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/debug[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/actuator[a-zA-Z0-9_/\-]*)["\']',
    ]

    routes = {}  # path -> method (evite les doublons, methode specifique > GET)

    # D'abord les routes avec methode
    for pattern, method in method_patterns:
        for match in re.findall(pattern, content):
            clean = match.split("?")[0]
            if len(clean) > 1 and not clean.endswith(static_extensions):
                routes[clean] = method

    # Ensuite les generiques (seulement si pas deja trouvees)
    for pattern in generic_patterns:
        for match in re.findall(pattern, content):
            clean = match.split("?")[0]
            if len(clean) > 1 and not clean.endswith(static_extensions) and clean not in routes:
                routes[clean] = "GET"

    return [{"path": path, "method": method} for path, method in routes.items()]
