"""Utilitaires HTTP pour le scanner.

Fournit des helpers pour effectuer des requetes HTTP securisees,
des requetes paralleles et un cache en memoire.
"""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from src.infra.logging import get_logger
from src.infra.config import settings
from src.infra.decorators import retry

logger = get_logger(__name__)

# ---------- Cache HTTP en memoire (TTL 5 min) ----------

_cache: dict[str, tuple[float, object]] = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 300  # 5 minutes


def _cache_key(url: str, method: str) -> str:
    return f"{method}:{url}"


def _cache_get(url: str, method: str):
    """Recupere une reponse du cache si elle n'a pas expire."""
    key = _cache_key(url, method)
    with _cache_lock:
        if key in _cache:
            ts, resp = _cache[key]
            if time.time() - ts < _CACHE_TTL:
                return resp
            del _cache[key]
    return None


def _cache_set(url: str, method: str, resp):
    """Stocke une reponse dans le cache."""
    key = _cache_key(url, method)
    with _cache_lock:
        _cache[key] = (time.time(), resp)


def clear_cache():
    """Vide le cache (appele entre les scans)."""
    with _cache_lock:
        _cache.clear()


# ---------- Requetes HTTP ----------

def safe_request(url: str, method: str = "GET", timeout: int | None = None, json_body: dict | None = None):
    """Effectue une requete HTTP avec gestion d'erreurs et cache.

    Les requetes GET sont mises en cache automatiquement (TTL 5 min).
    Les requetes POST/PUT/DELETE ne sont jamais cachees.

    Args:
        url: URL cible
        method: GET, POST, PUT, DELETE
        timeout: Timeout en secondes (default: settings.request_timeout)
        json_body: Corps JSON pour les requetes POST/PUT

    Returns:
        (response, None) si OK, (None, message_erreur) sinon.
    """
    if timeout is None:
        timeout = settings.request_timeout
    # Cache uniquement pour GET sans body
    if method == "GET" and json_body is None:
        cached = _cache_get(url, method)
        if cached is not None:
            return cached, None

    try:
        return _do_request(url, method, timeout, json_body)
    except (requests.ConnectionError, requests.Timeout) as e:
        return None, str(e)
    except requests.RequestException as e:
        return None, str(e)


@retry(max_attempts=2, base_delay=0.5, exceptions=(requests.ConnectionError, requests.Timeout))
def _do_request(url: str, method: str, timeout: int, json_body: dict | None):
    """Execute the actual HTTP request with retry on transient errors."""
    if method == "POST":
        resp = requests.post(url, json=json_body or {}, timeout=timeout, allow_redirects=False)
    elif method == "PUT":
        resp = requests.put(url, json=json_body or {}, timeout=timeout, allow_redirects=False)
    elif method == "DELETE":
        resp = requests.delete(url, timeout=timeout, allow_redirects=False)
    else:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)

    if resp.status_code >= 500:
        return None, f"Erreur serveur: {resp.status_code}"

    # Cacher les GET reussis
    if method == "GET" and json_body is None:
        _cache_set(url, method, resp)

    return resp, None


def parallel_requests(urls: list[tuple[str, str]], timeout: int = 3, max_workers: int = 10) -> list[tuple[str, str, object | None]]:
    """Execute des requetes HTTP en parallele.

    Utilise le cache automatiquement via safe_request.

    Args:
        urls: Liste de tuples (url, method)
        timeout: Timeout par requete
        max_workers: Nombre de threads paralleles

    Returns:
        Liste de tuples (url, method, response | None)
    """
    results = []

    def _fetch(url: str, method: str):
        resp, _ = safe_request(url, method=method, timeout=timeout)
        return url, method, resp

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_fetch, url, method): (url, method) for url, method in urls}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                url, method = futures[future]
                results.append((url, method, None))

    return results


def error_json(message: str) -> str:
    """Retourne un JSON d'erreur formate.

    Args:
        message: Message d'erreur

    Returns:
        JSON string {"error": "message"}
    """
    return json.dumps({"error": message})
