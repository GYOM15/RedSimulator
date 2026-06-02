"""Parse GraphQL schemas via introspection.

Envoie une requete d'introspection a un endpoint GraphQL et convertit
le schema en une liste d'ApiEndpoint exploitables par le scanner.

Chaque query est modelisee comme un endpoint GET-like et chaque mutation
comme un endpoint POST-like, avec les arguments comme parametres.
"""

from src.infra.decorators import logged
from src.infra.logging import get_logger
from src.scanner.http_utils import safe_request

from .models import ApiEndpoint, ApiParameter, ApiSpec

logger = get_logger(__name__)

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name } } }
        type { name kind ofType { name } }
      }
    }
  }
}
"""


def _graphql_type_to_string(type_info: dict) -> str:
    """Convertit un type GraphQL en chaine lisible.

    Gere les types wrappeurs (NON_NULL, LIST) via ofType.

    Args:
        type_info: Dictionnaire de type GraphQL.

    Returns:
        Representation lisible du type (ex: "String", "[User]", "ID!").
    """
    if not isinstance(type_info, dict):
        return "String"

    name = type_info.get("name")
    kind = type_info.get("kind", "")
    of_type = type_info.get("ofType")

    if name:
        return name

    if kind == "NON_NULL" and isinstance(of_type, dict):
        inner = _graphql_type_to_string(of_type)
        return f"{inner}!"

    if kind == "LIST" and isinstance(of_type, dict):
        inner = _graphql_type_to_string(of_type)
        return f"[{inner}]"

    if isinstance(of_type, dict) and of_type.get("name"):
        return of_type["name"]

    return "String"


def _graphql_type_to_param_type(type_info: dict) -> str:
    """Mappe un type GraphQL vers un type de parametre simplifie.

    Args:
        type_info: Dictionnaire de type GraphQL.

    Returns:
        Type simplifie compatible avec ApiParameter ("string", "integer", etc.).
    """
    type_str = _graphql_type_to_string(type_info).rstrip("!").strip("[]")

    mapping = {
        "String": "string",
        "Int": "integer",
        "Float": "number",
        "Boolean": "boolean",
        "ID": "string",
    }
    return mapping.get(type_str, "object")


def _is_builtin_type(type_name: str) -> bool:
    """Verifie si un type est un type interne GraphQL (a ignorer).

    Args:
        type_name: Nom du type.

    Returns:
        True si le type est interne (commence par __ ou est un scalaire de base).
    """
    if type_name.startswith("__"):
        return True
    return type_name in {"String", "Int", "Float", "Boolean", "ID"}


@logged
def introspect_graphql(url: str, session=None) -> ApiSpec | None:
    """Envoie une requete d'introspection et parse le schema GraphQL.

    Tente de decouvrir le schema via la query d'introspection standard.
    Si l'introspection est desactivee, retourne None.

    Args:
        url: URL de l'endpoint GraphQL.
        session: Session HTTP optionnelle (non utilisee, pour compatibilite).

    Returns:
        ApiSpec avec les queries et mutations, ou None si echec.
    """
    logger.info("Introspection GraphQL sur %s...", url)

    resp, error = safe_request(
        url,
        method="POST",
        json_body={"query": INTROSPECTION_QUERY},
        timeout=10,
    )

    if resp is None:
        logger.debug("Requete d'introspection echouee: %s", error)
        return None

    # Verifier que c'est bien du JSON avec des donnees GraphQL
    try:
        data = resp.json()
    except Exception:
        logger.debug("Reponse non-JSON depuis %s", url)
        return None

    if not isinstance(data, dict):
        return None

    # Verifier la presence du schema
    schema_data = data.get("data", {})
    if not isinstance(schema_data, dict):
        # Certains serveurs retournent des erreurs
        errors = data.get("errors", [])
        if errors:
            logger.debug("Introspection refusee: %s", errors[0].get("message", ""))
        return None

    schema = schema_data.get("__schema")
    if not isinstance(schema, dict):
        return None

    # Extraire les noms des types racine
    query_type_name = ""
    mutation_type_name = ""

    query_type = schema.get("queryType")
    if isinstance(query_type, dict):
        query_type_name = query_type.get("name", "")

    mutation_type = schema.get("mutationType")
    if isinstance(mutation_type, dict):
        mutation_type_name = mutation_type.get("name", "")

    # Indexer les types par nom
    types = schema.get("types", [])
    if not isinstance(types, list):
        return None

    type_map = {}
    for t in types:
        if isinstance(t, dict) and "name" in t:
            type_map[t["name"]] = t

    endpoints = []

    # Parser les queries
    if query_type_name and query_type_name in type_map:
        query_type_def = type_map[query_type_name]
        fields = query_type_def.get("fields") or []
        for field in fields:
            if not isinstance(field, dict):
                continue
            ep = _field_to_endpoint(field, url, "GET", "query")
            if ep:
                endpoints.append(ep)

    # Parser les mutations
    if mutation_type_name and mutation_type_name in type_map:
        mutation_type_def = type_map[mutation_type_name]
        fields = mutation_type_def.get("fields") or []
        for field in fields:
            if not isinstance(field, dict):
                continue
            ep = _field_to_endpoint(field, url, "POST", "mutation")
            if ep:
                endpoints.append(ep)

    # Compter les types custom (pour info)
    custom_types = [
        t["name"]
        for t in types
        if isinstance(t, dict)
        and "name" in t
        and not _is_builtin_type(t["name"])
        and t.get("kind") == "OBJECT"
        and t["name"] not in (query_type_name, mutation_type_name)
    ]

    logger.info(
        "GraphQL: %d queries, %d mutations, %d types custom",
        len([e for e in endpoints if e.method == "GET"]),
        len([e for e in endpoints if e.method == "POST"]),
        len(custom_types),
    )

    return ApiSpec(
        format="graphql",
        version="introspection",
        base_url=url,
        title=f"GraphQL ({url})",
        endpoints=endpoints,
        auth_schemes={},
    )


def _field_to_endpoint(
    field: dict, url: str, method: str, operation_type: str
) -> ApiEndpoint | None:
    """Convertit un champ GraphQL en ApiEndpoint.

    Args:
        field: Definition du champ (query ou mutation).
        url: URL de l'endpoint GraphQL.
        method: Methode HTTP equivalente ("GET" pour query, "POST" pour mutation).
        operation_type: "query" ou "mutation".

    Returns:
        ApiEndpoint ou None si le champ est invalide.
    """
    name = field.get("name", "")
    if not name:
        return None

    # Arguments -> parametres
    parameters = []
    args = field.get("args") or []
    for arg in args:
        if not isinstance(arg, dict):
            continue
        arg_name = arg.get("name", "")
        if not arg_name:
            continue

        arg_type = arg.get("type", {})
        param_type = _graphql_type_to_param_type(arg_type)
        type_str = _graphql_type_to_string(arg_type)

        # Un argument NON_NULL est requis
        is_required = type_str.endswith("!")

        parameters.append(
            ApiParameter(
                name=arg_name,
                location="body",
                param_type=param_type,
                required=is_required,
            )
        )

    # Type de retour -> description
    return_type = field.get("type", {})
    return_type_str = _graphql_type_to_string(return_type)

    description = f"GraphQL {operation_type}: {name} -> {return_type_str}"

    return ApiEndpoint(
        path=f"/graphql#{operation_type}.{name}",
        method=method,
        parameters=parameters,
        tags=[operation_type],
        description=description,
    )
