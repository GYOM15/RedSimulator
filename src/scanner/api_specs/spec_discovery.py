"""Auto-decouverte de specifications API sur une cible.

Sonde les chemins courants ou l'on trouve typiquement des specs
OpenAPI/Swagger et des endpoints GraphQL, puis parse les specs trouvees.
"""

from src.infra.decorators import logged
from src.infra.logging import get_logger
from src.scanner.http_utils import safe_request

from .graphql_parser import introspect_graphql
from .models import ApiSpec
from .openapi_parser import parse_openapi

logger = get_logger(__name__)

COMMON_SPEC_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/openapi.json",
    "/openapi.yaml",
    "/v3/api-docs",
    "/v2/api-docs",
    "/.well-known/openapi.json",
    "/graphql",
    "/_graphql",
    "/api/graphql",
    "/graphql/schema",
]

# Chemins qui sont probablement des endpoints GraphQL
_GRAPHQL_PATH_PATTERNS = {"graphql", "_graphql"}


def _is_graphql_path(path: str) -> bool:
    """Determine si un chemin est probablement un endpoint GraphQL.

    Args:
        path: Chemin a tester.

    Returns:
        True si le chemin correspond a un pattern GraphQL connu.
    """
    last_segment = path.rstrip("/").split("/")[-1].lower()
    return last_segment in _GRAPHQL_PATH_PATTERNS


def _try_parse_json(resp) -> dict | None:
    """Tente de parser la reponse comme JSON.

    Args:
        resp: Objet Response HTTP.

    Returns:
        Dictionnaire parse ou None si echec.
    """
    try:
        data = resp.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return None


def _try_parse_yaml(text: str) -> dict | None:
    """Tente de parser le texte comme YAML.

    Gere gracieusement l'absence du module yaml.

    Args:
        text: Contenu textuel a parser.

    Returns:
        Dictionnaire parse ou None si echec / yaml non installe.
    """
    try:
        import yaml

        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
    except ImportError:
        logger.debug("Module yaml non installe — YAML specs non supportees")
    except Exception:
        pass
    return None


def _is_openapi_or_swagger(data: dict) -> bool:
    """Verifie si un dict est une spec OpenAPI ou Swagger.

    Args:
        data: Dictionnaire a verifier.

    Returns:
        True si le dictionnaire contient les cles 'openapi' ou 'swagger'.
    """
    return "openapi" in data or "swagger" in data


@logged
def discover_api_specs(base_url: str, session=None) -> list[ApiSpec]:
    """Sonde les chemins courants pour decouvrir des specifications API.

    Pour chaque chemin dans COMMON_SPEC_PATHS :
    - Si c'est un chemin GraphQL, tente une introspection
    - Sinon, tente un GET et parse la reponse comme OpenAPI/Swagger
    - Supporte les reponses JSON et YAML

    Args:
        base_url: URL de base de la cible (ex: http://localhost:3000).
        session: Session HTTP optionnelle (non utilisee, pour compatibilite).

    Returns:
        Liste des ApiSpec decouvertes.
    """
    base_url = base_url.rstrip("/")
    specs = []
    discovered_paths = set()

    for path in COMMON_SPEC_PATHS:
        url = f"{base_url}{path}"

        # Eviter les doublons
        if url in discovered_paths:
            continue

        try:
            spec = _try_graphql(url) if _is_graphql_path(path) else _try_openapi(url, base_url)

            if spec is not None:
                specs.append(spec)
                discovered_paths.add(url)
                logger.info("Spec API decouverte: %s (%s)", path, spec.format)
        except Exception as e:
            logger.debug("Erreur en sondant %s: %s", path, e)

    logger.info("%d specification(s) API decouverte(s)", len(specs))
    return specs


def _try_openapi(url: str, base_url: str) -> ApiSpec | None:
    """Tente de recuperer et parser une spec OpenAPI/Swagger.

    Essaie d'abord JSON, puis YAML si le contenu n'est pas du JSON.

    Args:
        url: URL complete du document de specification.
        base_url: URL de base de la cible.

    Returns:
        ApiSpec parsee ou None si echec.
    """
    resp, _error = safe_request(url, timeout=5)
    if resp is None:
        return None

    # Ignorer les erreurs HTTP
    if resp.status_code not in (200, 301, 302):
        return None

    # Tenter JSON
    data = _try_parse_json(resp)

    # Tenter YAML si pas du JSON
    if data is None and resp.text:
        content_type = resp.headers.get("Content-Type", "").lower()
        if "yaml" in content_type or "yml" in content_type or url.endswith((".yaml", ".yml")):
            data = _try_parse_yaml(resp.text)
        elif "json" not in content_type and "html" not in content_type:
            # Contenu ambigu — tenter YAML en dernier recours
            data = _try_parse_yaml(resp.text)

    if data is None:
        return None

    # Verifier que c'est bien une spec OpenAPI/Swagger
    if not _is_openapi_or_swagger(data):
        return None

    return parse_openapi(data, base_url=base_url)


def _try_graphql(url: str) -> ApiSpec | None:
    """Tente une introspection GraphQL sur l'URL.

    Args:
        url: URL de l'endpoint GraphQL.

    Returns:
        ApiSpec avec le schema GraphQL, ou None si echec.
    """
    return introspect_graphql(url)
