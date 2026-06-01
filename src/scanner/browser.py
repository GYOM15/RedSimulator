"""Gestionnaire de navigateur Playwright singleton.

Evite de lancer un nouveau processus Chromium a chaque appel.
Un seul navigateur est partage entre tous les modules du scanner.
"""

import contextlib

from src.infra.exceptions import ExternalServiceError
from src.infra.logging import get_logger

logger = get_logger(__name__)

_playwright = None
_browser = None


def get_browser():
    """Retourne une instance partagee du navigateur Chromium.

    Le navigateur est lance une seule fois et reutilise.
    Retourne None si Playwright n'est pas installe.
    """
    global _playwright, _browser

    if _browser is not None:
        return _browser

    try:
        from playwright.sync_api import sync_playwright

        _playwright = sync_playwright().start()
        _browser = _playwright.chromium.launch(headless=True)
        logger.info("Chromium demarre (singleton)")
        return _browser
    except Exception as e:
        err = ExternalServiceError(
            f"Playwright non disponible: {e}",
            details={"original_error": type(e).__name__},
        )
        logger.warning("%s", err)
        return None


def new_page(url: str, timeout: int = 10000):
    """Ouvre une nouvelle page et navigue vers l'URL.

    Args:
        url: URL a ouvrir
        timeout: Timeout en millisecondes

    Returns:
        Page Playwright ou None si echec.
    """
    browser = get_browser()
    if browser is None:
        return None

    try:
        page = browser.new_page()
        page.goto(url, wait_until="networkidle", timeout=timeout)
        return page
    except Exception as e:
        err = ExternalServiceError(
            f"Navigation echouee ({url}): {e}",
            details={"url": url, "original_error": type(e).__name__},
        )
        logger.error("%s", err)
        return None


def close_page(page):
    """Ferme une page sans fermer le navigateur."""
    if page:
        with contextlib.suppress(Exception):
            page.close()


def shutdown():
    """Ferme le navigateur et Playwright."""
    global _playwright, _browser
    if _browser:
        with contextlib.suppress(Exception):
            _browser.close()
        _browser = None
    if _playwright:
        with contextlib.suppress(Exception):
            _playwright.stop()
        _playwright = None
