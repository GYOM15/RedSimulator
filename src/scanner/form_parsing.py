"""Analyse de formulaires HTML (statique et dynamique).

Detecte les formulaires dans les pages web en combinant :
- Analyse statique avec BeautifulSoup (formulaires HTML classiques)
- Analyse dynamique avec Playwright (formulaires SPA : Angular, React, etc.)
"""

import re

from bs4 import BeautifulSoup

from src.infra.logging import get_logger
from .http_utils import safe_request

logger = get_logger(__name__)

# Noms de champs a ignorer (barres de recherche globales, etc.)
IGNORED_FIELD_NAMES = {"search", "q", "searchQuery"}
# Pattern pour les champs Angular Material auto-generes (mat-input-0, mat-input-1, ...)
IGNORED_FIELD_PATTERN = re.compile(r"^mat-input-\d+$")


def analyze_static_forms(url: str) -> list:
    """Analyse statique des formulaires avec BeautifulSoup.

    Args:
        url: URL complete de la page a analyser

    Returns:
        Liste de formulaires avec leurs champs.
    """
    resp, error = safe_request(url)
    if resp is None or resp.status_code != 200:
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    forms_info = []

    for form in soup.find_all("form"):
        fields = _extract_fields(form, ["input", "select", "textarea"])

        if fields:
            forms_info.append({
                "action": form.get("action", ""),
                "method": form.get("method", "GET"),
                "fields": fields,
                "source": "static",
            })

    return forms_info


def analyze_dynamic_forms(url: str) -> list:
    """Analyse dynamique des formulaires avec Playwright.

    Utilise le navigateur singleton pour detecter
    les formulaires generes par les frameworks JS.

    Args:
        url: URL complete de la page a analyser

    Returns:
        Liste de formulaires avec leurs champs.
    """
    from .browser import new_page, close_page

    forms_info = []
    page = new_page(url)
    if page is None:
        return forms_info

    try:
        forms_info.extend(_extract_rendered_forms(page))

        orphan_form = _extract_orphan_inputs(page, url)
        if orphan_form:
            forms_info.append(orphan_form)
    except Exception as e:
        logger.warning("Analyse dynamique echouee: %s", e)
    finally:
        close_page(page)

    return forms_info


def analyze_angular_forms(target: str) -> list:
    """Navigue les routes Angular et detecte les formulaires.

    Utilise le navigateur singleton. Cette fonction est gardee
    pour le fallback — l'agent autonome appelle form_analyzer directement.

    Args:
        target: URL de base de la cible

    Returns:
        Liste de formulaires avec leurs champs.
    """
    from .browser import new_page, close_page

    # Routes Angular courantes a tester
    angular_routes = [
        "/#/login",
        "/#/register",
        "/#/contact",
        "/#/forgot-password",
        "/#/complain",
        "/#/chatbot",
        "/#/search",
        "/#/basket",
        "/#/address/select",
        "/#/payment/shop",
    ]

    base_url = target.rstrip("/")
    all_forms = []

    for route in angular_routes:
        url = f"{base_url}{route}"
        page = new_page(url, timeout=8000)
        if page is None:
            continue

        try:
            forms = _extract_rendered_forms(page)

            orphan = _extract_orphan_inputs(page, url)
            if orphan:
                forms.append(orphan)

            for form in forms:
                form["endpoint"] = route
                if form.get("fields"):
                    all_forms.append(form)
                    logger.debug("%s -> %d champs", route, len(form['fields']))

        except Exception:
            pass
        finally:
            close_page(page)

    logger.debug("%d formulaires Angular detectes", len(all_forms))
    return all_forms


# ---------- Helpers prives ----------

def _extract_fields(container, selectors: list[str]) -> list[dict]:
    """Extrait les champs de formulaire depuis un conteneur BeautifulSoup."""
    fields = []
    for input_tag in container.find_all(selectors):
        field_name = input_tag.get("name")
        if field_name:
            fields.append({
                "name": field_name,
                "type": input_tag.get("type", "text"),
            })
    return fields


def _extract_rendered_forms(page) -> list[dict]:
    """Extrait les formulaires depuis le DOM rendu par Playwright."""
    forms = []
    for form_el in page.query_selector_all("form"):
        fields = []
        for input_el in form_el.query_selector_all("input, select, textarea"):
            name = input_el.get_attribute("name") or input_el.get_attribute("id") or ""
            input_type = input_el.get_attribute("type") or "text"
            if name:
                fields.append({"name": name, "type": input_type})

        if fields:
            forms.append({
                "action": form_el.get_attribute("action") or "",
                "method": form_el.get_attribute("method") or "POST",
                "fields": fields,
                "source": "dynamic",
            })

    return forms


def _extract_orphan_inputs(page, url: str) -> dict | None:
    """Detecte les champs hors balise <form> (Angular reactive forms, etc.)."""
    orphan_inputs = page.evaluate("""() => {
        const inputs = document.querySelectorAll('input:not(form input), textarea:not(form textarea)');
        return Array.from(inputs).map(el => ({
            name: el.name || el.id || el.getAttribute('ng-model') || el.getAttribute('formcontrolname') || '',
            type: el.type || 'text',
            placeholder: el.placeholder || ''
        })).filter(f => f.name);
    }""")

    # Filtrer les champs auto-generes et les searchbars
    filtered = [f for f in orphan_inputs
                if f["name"] not in IGNORED_FIELD_NAMES
                and not IGNORED_FIELD_PATTERN.match(f["name"])]

    if filtered:
        return {
            "action": url,
            "method": "POST",
            "fields": filtered,
            "source": "dynamic-orphan",
        }

    return None
