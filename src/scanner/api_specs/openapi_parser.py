"""Parse OpenAPI 3.x and Swagger 2.0 specifications.

Gere les deux formats principaux de documentation API REST :
- OpenAPI 3.0 / 3.1 (cle 'openapi' dans le document)
- Swagger 2.0 (cle 'swagger' dans le document)

Le parser est defensif : les specs malformees sont gerees gracieusement.
"""

from src.infra.decorators import logged
from src.infra.logging import get_logger

from .models import ApiEndpoint, ApiParameter, ApiSpec

logger = get_logger(__name__)


def _resolve_ref(ref_path: str, spec_data: dict) -> dict:
    """Resout une reference $ref (un seul niveau de profondeur).

    Supporte les references locales de la forme '#/components/schemas/User'
    ou '#/definitions/User'.

    Args:
        ref_path: Chemin de la reference (ex: '#/components/schemas/User').
        spec_data: Document de specification complet.

    Returns:
        Le schema resolu, ou un dict vide si la reference est invalide.
    """
    if not ref_path or not ref_path.startswith("#/"):
        return {}

    parts = ref_path[2:].split("/")
    current = spec_data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            logger.debug("Reference non resolue: %s", ref_path)
            return {}
    return current if isinstance(current, dict) else {}


def _resolve_schema(schema: dict, spec_data: dict) -> dict:
    """Resout un schema, en suivant les $ref si necessaire.

    Args:
        schema: Schema potentiellement avec $ref.
        spec_data: Document de specification complet.

    Returns:
        Schema resolu (sans $ref au premier niveau).
    """
    if not isinstance(schema, dict):
        return {}
    if "$ref" in schema:
        return _resolve_ref(schema["$ref"], spec_data)
    return schema


def _extract_type(schema: dict, spec_data: dict) -> str:
    """Extrait le type d'un schema (avec resolution $ref).

    Args:
        schema: Schema du parametre ou du champ.
        spec_data: Document de specification complet.

    Returns:
        Type sous forme de chaine ("string", "integer", "object", etc.).
    """
    resolved = _resolve_schema(schema, spec_data)
    return resolved.get("type", "string")


def _extract_auth_schemes_openapi3(spec_data: dict) -> dict:
    """Extrait les schemas d'authentification OpenAPI 3.x.

    Cherche dans components.securitySchemes.

    Returns:
        Dict {nom: type} des schemas d'auth (ex: {"bearerAuth": "http/bearer"}).
    """
    schemes = {}
    security_schemes = spec_data.get("components", {}).get("securitySchemes", {})

    for name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            continue
        scheme_type = scheme.get("type", "")
        if scheme_type == "http":
            sub_scheme = scheme.get("scheme", "")
            schemes[name] = f"http/{sub_scheme}"
        elif scheme_type == "apiKey":
            location = scheme.get("in", "header")
            key_name = scheme.get("name", "")
            schemes[name] = f"apiKey({location}:{key_name})"
        elif scheme_type == "oauth2":
            flows = list(scheme.get("flows", {}).keys())
            schemes[name] = f"oauth2({','.join(flows)})"
        elif scheme_type == "openIdConnect":
            schemes[name] = "openIdConnect"
        else:
            schemes[name] = scheme_type

    return schemes


def _extract_auth_schemes_swagger2(spec_data: dict) -> dict:
    """Extrait les schemas d'authentification Swagger 2.0.

    Cherche dans securityDefinitions.

    Returns:
        Dict {nom: type} des schemas d'auth.
    """
    schemes = {}
    security_defs = spec_data.get("securityDefinitions", {})

    for name, definition in security_defs.items():
        if not isinstance(definition, dict):
            continue
        def_type = definition.get("type", "")
        if def_type == "apiKey":
            location = definition.get("in", "header")
            key_name = definition.get("name", "")
            schemes[name] = f"apiKey({location}:{key_name})"
        elif def_type == "oauth2":
            flow = definition.get("flow", "")
            schemes[name] = f"oauth2({flow})"
        elif def_type == "basic":
            schemes[name] = "http/basic"
        else:
            schemes[name] = def_type

    return schemes


def _get_operation_auth(operation: dict, global_security: list, auth_schemes: dict) -> list[str]:
    """Determine les schemas d'auth pour une operation specifique.

    L'operation peut surcharger la securite globale.

    Args:
        operation: Definition de l'operation.
        global_security: Liste de securite globale du document.
        auth_schemes: Schemas d'auth resolus.

    Returns:
        Liste des noms de schemas d'auth applicables.
    """
    security = operation.get("security", global_security)
    if not security:
        return []

    result = []
    for sec_requirement in security:
        if isinstance(sec_requirement, dict):
            for scheme_name in sec_requirement:
                if scheme_name in auth_schemes:
                    result.append(auth_schemes[scheme_name])
                else:
                    result.append(scheme_name)
    return result


def _parse_openapi3_parameters(
    operation: dict, path_params: list, spec_data: dict
) -> list[ApiParameter]:
    """Parse les parametres d'une operation OpenAPI 3.x.

    Combine les parametres du path et de l'operation.

    Args:
        operation: Definition de l'operation.
        path_params: Parametres definis au niveau du path.
        spec_data: Document de specification complet.

    Returns:
        Liste de ApiParameter.
    """
    params = []
    seen_names = set()

    # Parametres du path (herites)
    for param in path_params:
        param = _resolve_schema(param, spec_data)
        name = param.get("name", "")
        if not name or name in seen_names:
            continue
        seen_names.add(name)

        schema = _resolve_schema(param.get("schema", {}), spec_data)
        params.append(
            ApiParameter(
                name=name,
                location=param.get("in", "query"),
                param_type=schema.get("type", "string"),
                required=param.get("required", False),
                example=str(param.get("example", schema.get("example", ""))),
            )
        )

    # Parametres de l'operation (surcharge ceux du path)
    for param in operation.get("parameters", []):
        param = _resolve_schema(param, spec_data)
        name = param.get("name", "")
        if not name or name in seen_names:
            continue
        seen_names.add(name)

        schema = _resolve_schema(param.get("schema", {}), spec_data)
        params.append(
            ApiParameter(
                name=name,
                location=param.get("in", "query"),
                param_type=schema.get("type", "string"),
                required=param.get("required", False),
                example=str(param.get("example", schema.get("example", ""))),
            )
        )

    # requestBody -> parametres body
    request_body = operation.get("requestBody", {})
    if isinstance(request_body, dict) and "$ref" in request_body:
        request_body = _resolve_ref(request_body["$ref"], spec_data)

    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        # Prendre le premier content-type disponible
        for _ct, media_type in content.items():
            if not isinstance(media_type, dict):
                continue
            schema = _resolve_schema(media_type.get("schema", {}), spec_data)
            body_required = request_body.get("required", False)

            # Extraire les proprietes du schema body
            properties = schema.get("properties", {})
            required_props = set(schema.get("required", []))

            for prop_name, prop_schema in properties.items():
                if prop_name in seen_names:
                    continue
                seen_names.add(prop_name)
                prop_schema = _resolve_schema(prop_schema, spec_data)
                params.append(
                    ApiParameter(
                        name=prop_name,
                        location="body",
                        param_type=prop_schema.get("type", "string"),
                        required=body_required and prop_name in required_props,
                        example=str(prop_schema.get("example", "")),
                    )
                )
            break  # Un seul content-type suffit

    return params


def _parse_swagger2_parameters(
    operation: dict, path_params: list, spec_data: dict
) -> list[ApiParameter]:
    """Parse les parametres d'une operation Swagger 2.0.

    En Swagger 2.0, les parametres body sont dans la liste 'parameters'
    avec "in": "body".

    Args:
        operation: Definition de l'operation.
        path_params: Parametres definis au niveau du path.
        spec_data: Document de specification complet.

    Returns:
        Liste de ApiParameter.
    """
    params = []
    seen_names = set()

    all_params = list(path_params) + list(operation.get("parameters", []))

    for param in all_params:
        param = _resolve_schema(param, spec_data)
        name = param.get("name", "")
        if not name or name in seen_names:
            continue
        seen_names.add(name)

        location = param.get("in", "query")

        if location == "body":
            # Le parametre body a un schema complet
            schema = _resolve_schema(param.get("schema", {}), spec_data)
            body_required = param.get("required", False)

            properties = schema.get("properties", {})
            required_props = set(schema.get("required", []))

            if properties:
                for prop_name, prop_schema in properties.items():
                    if prop_name in seen_names:
                        continue
                    seen_names.add(prop_name)
                    prop_schema = _resolve_schema(prop_schema, spec_data)
                    params.append(
                        ApiParameter(
                            name=prop_name,
                            location="body",
                            param_type=prop_schema.get("type", "string"),
                            required=body_required and prop_name in required_props,
                            example=str(prop_schema.get("example", "")),
                        )
                    )
            else:
                # Schema simple sans proprietes
                params.append(
                    ApiParameter(
                        name=name,
                        location="body",
                        param_type=schema.get("type", "object"),
                        required=body_required,
                    )
                )
        else:
            params.append(
                ApiParameter(
                    name=name,
                    location=location,
                    param_type=param.get("type", "string"),
                    required=param.get("required", False),
                    example=str(param.get("example", param.get("default", ""))),
                )
            )

    return params


def _get_request_body_schema(operation: dict, spec_data: dict) -> dict | None:
    """Extrait le schema du corps de la requete.

    Args:
        operation: Definition de l'operation.
        spec_data: Document de specification complet.

    Returns:
        Schema du corps ou None.
    """
    # OpenAPI 3.x
    request_body = operation.get("requestBody", {})
    if isinstance(request_body, dict) and "$ref" in request_body:
        request_body = _resolve_ref(request_body["$ref"], spec_data)

    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        for _ct, media_type in content.items():
            if isinstance(media_type, dict):
                schema = media_type.get("schema", {})
                if schema:
                    return _resolve_schema(schema, spec_data) or None
                break

    # Swagger 2.0 — chercher le parametre body
    for param in operation.get("parameters", []):
        param = _resolve_schema(param, spec_data)
        if param.get("in") == "body" and "schema" in param:
            return _resolve_schema(param["schema"], spec_data) or None

    return None


@logged
def parse_openapi(spec_data: dict, base_url: str = "") -> ApiSpec:
    """Parse un document OpenAPI/Swagger en ApiSpec.

    Detecte automatiquement le format (OpenAPI 3.x vs Swagger 2.0)
    et extrait tous les endpoints, parametres et schemas d'auth.

    Args:
        spec_data: Dictionnaire du document de specification.
        base_url: URL de base (utilisee si non presente dans la spec).

    Returns:
        ApiSpec avec tous les endpoints decouverts.
    """
    # Detection du format
    is_openapi3 = "openapi" in spec_data
    is_swagger2 = "swagger" in spec_data

    if is_openapi3:
        spec_format = "openapi3"
        version = str(spec_data.get("openapi", "3.0.0"))
        auth_schemes = _extract_auth_schemes_openapi3(spec_data)

        # Extraire le base_url depuis servers
        if not base_url:
            servers = spec_data.get("servers", [])
            if servers and isinstance(servers[0], dict):
                base_url = servers[0].get("url", "")
    elif is_swagger2:
        spec_format = "swagger2"
        version = str(spec_data.get("swagger", "2.0"))
        auth_schemes = _extract_auth_schemes_swagger2(spec_data)

        # Construire le base_url depuis host + basePath
        if not base_url:
            host = spec_data.get("host", "")
            base_path = spec_data.get("basePath", "")
            schemes = spec_data.get("schemes", ["https"])
            scheme = schemes[0] if schemes else "https"
            if host:
                base_url = f"{scheme}://{host}{base_path}"
    else:
        logger.warning("Format de specification non reconnu (ni openapi, ni swagger)")
        return ApiSpec(
            format="unknown",
            version="",
            base_url=base_url,
            title=spec_data.get("info", {}).get("title", "Unknown"),
            auth_schemes={},
        )

    title = ""
    info = spec_data.get("info", {})
    if isinstance(info, dict):
        title = info.get("title", "")

    global_security = spec_data.get("security", [])
    endpoints = []

    paths = spec_data.get("paths", {})
    if not isinstance(paths, dict):
        logger.warning("Champ 'paths' manquant ou invalide dans la spec")
        return ApiSpec(
            format=spec_format,
            version=version,
            base_url=base_url,
            title=title,
            auth_schemes=auth_schemes,
        )

    http_methods = {"get", "post", "put", "delete", "patch", "options", "head"}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Parametres au niveau du path (herites par toutes les operations)
        path_params = path_item.get("parameters", [])
        if not isinstance(path_params, list):
            path_params = []

        for method in http_methods:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue

            # Tags
            tags = operation.get("tags", [])
            if not isinstance(tags, list):
                tags = []

            # Description
            description = operation.get("summary", "") or operation.get("description", "")
            if not isinstance(description, str):
                description = str(description)

            # Parametres
            if is_openapi3:
                parameters = _parse_openapi3_parameters(operation, path_params, spec_data)
            else:
                parameters = _parse_swagger2_parameters(operation, path_params, spec_data)

            # Auth
            op_auth = _get_operation_auth(operation, global_security, auth_schemes)

            # Schema du body
            body_schema = _get_request_body_schema(operation, spec_data)

            endpoint = ApiEndpoint(
                path=path,
                method=method.upper(),
                parameters=parameters,
                request_body_schema=body_schema,
                auth_schemes=op_auth,
                tags=tags,
                description=description[:500],  # Tronquer les descriptions longues
            )
            endpoints.append(endpoint)

    logger.info(
        "Spec %s '%s' parsee: %d endpoints, %d schemas d'auth",
        spec_format,
        title,
        len(endpoints),
        len(auth_schemes),
    )

    return ApiSpec(
        format=spec_format,
        version=version,
        base_url=base_url,
        title=title,
        endpoints=endpoints,
        auth_schemes=auth_schemes,
    )
