"""Modeles de donnees pour les specifications API.

Represente les endpoints, parametres et schemas d'authentification
extraits de specifications OpenAPI, Swagger et GraphQL.
"""

from dataclasses import dataclass, field


@dataclass
class ApiParameter:
    """Parametre d'un endpoint API.

    Attributes:
        name: Nom du parametre.
        location: Emplacement du parametre ("query", "header", "path", "body", "cookie").
        param_type: Type du parametre ("string", "integer", "boolean", "object", "array").
        required: Indique si le parametre est obligatoire.
        example: Valeur d'exemple pour le parametre.
    """

    name: str
    location: str  # "query", "header", "path", "body", "cookie"
    param_type: str  # "string", "integer", "boolean", "object", "array"
    required: bool = False
    example: str = ""


@dataclass
class ApiEndpoint:
    """Endpoint decouvert dans une specification API.

    Attributes:
        path: Chemin de l'endpoint (ex: /api/users/{id}).
        method: Methode HTTP (GET, POST, PUT, DELETE, etc.).
        parameters: Liste des parametres de l'endpoint.
        request_body_schema: Schema du corps de la requete (si applicable).
        auth_schemes: Schemas d'authentification requis.
        tags: Tags/categories de l'endpoint.
        description: Description de l'endpoint.
    """

    path: str
    method: str
    parameters: list[ApiParameter] = field(default_factory=list)
    request_body_schema: dict | None = None
    auth_schemes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class ApiSpec:
    """Specification API complete (OpenAPI, Swagger ou GraphQL).

    Attributes:
        format: Format de la spec ("openapi3", "swagger2", "graphql").
        version: Version de la specification.
        base_url: URL de base de l'API.
        title: Titre de l'API.
        endpoints: Liste des endpoints decouverts.
        auth_schemes: Schemas d'authentification globaux.
    """

    format: str  # "openapi3", "swagger2", "graphql"
    version: str
    base_url: str
    title: str
    endpoints: list[ApiEndpoint] = field(default_factory=list)
    auth_schemes: dict = field(default_factory=dict)
