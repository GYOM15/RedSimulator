"""Package api_specs — Decouverte et parsing de specifications API.

Supporte les formats OpenAPI 3.x, Swagger 2.0 et GraphQL.
Fournit des fonctions pour :
- Parser des specs OpenAPI/Swagger
- Introspecter des schemas GraphQL
- Decouvrir automatiquement les specs sur une cible
- Convertir les endpoints API en modeles EndpointInfo du scanner
"""

from src.infra.logging import get_logger
from src.models.scan_result import EndpointInfo

from .graphql_parser import introspect_graphql
from .models import ApiEndpoint, ApiParameter, ApiSpec
from .openapi_parser import parse_openapi
from .spec_discovery import discover_api_specs

logger = get_logger(__name__)


def api_spec_to_endpoints(specs: list[ApiSpec]) -> list[EndpointInfo]:
    """Convertit les endpoints des specs API en EndpointInfo du scanner.

    Cree des objets EndpointInfo (utilises par ScanResult) a partir
    des ApiEndpoint extraits des specifications API.

    Args:
        specs: Liste de specifications API decouvertes.

    Returns:
        Liste d'EndpointInfo prets a etre integres dans un ScanResult.
    """
    endpoints = []
    seen = set()  # Eviter les doublons (path, method)

    for spec in specs:
        for api_ep in spec.endpoints:
            key = (api_ep.path, api_ep.method)
            if key in seen:
                continue
            seen.add(key)

            # Extraire les noms de parametres
            param_names = [p.name for p in api_ep.parameters]

            # Determiner si l'auth est requise
            auth_required = bool(api_ep.auth_schemes)

            endpoint = EndpointInfo(
                path=api_ep.path,
                method=api_ep.method,
                status_code=0,  # Inconnu — la spec ne donne pas le status actuel
                auth_required=auth_required,
                parameters=param_names,
            )
            endpoints.append(endpoint)

    logger.info(
        "%d endpoint(s) convertis depuis %d spec(s) API",
        len(endpoints),
        len(specs),
    )
    return endpoints


__all__ = [
    "ApiEndpoint",
    "ApiParameter",
    "ApiSpec",
    "api_spec_to_endpoints",
    "discover_api_specs",
    "introspect_graphql",
    "parse_openapi",
]
