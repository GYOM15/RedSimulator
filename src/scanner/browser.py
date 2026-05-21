"""Gestionnaire de navigateur Playwright singleton.

Evite de lancer un nouveau processus Chromium a chaque appel.
Un seul navigateur est partage entre tous les modules du scanner.
"""

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
        print("[BROWSER] Chromium demarre (singleton)")
        return _browser
    except Exception as e:
        print(f"[BROWSER] Playwright non disponible: {e}")
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
        print(f"[BROWSER] Navigation echouee ({url}): {e}")
        return None


def close_page(page):
    """Ferme une page sans fermer le navigateur."""
    if page:
        try:
            page.close()
        except Exception:
            pass


def shutdown():
    """Ferme le navigateur et Playwright."""
    global _playwright, _browser
    if _browser:
        try:
            _browser.close()
        except Exception:
            pass
        _browser = None
    if _playwright:
        try:
            _playwright.stop()
        except Exception:
            pass
        _playwright = None
