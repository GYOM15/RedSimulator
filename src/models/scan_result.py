"""Modeles Pydantic pour les resultats de scan.

Ces modeles representent la sortie du module Scanner (agent ReAct).
Ils capturent les ports ouverts, endpoints decouverts, headers de securite
et formulaires trouves sur la cible.
"""

from pydantic import BaseModel, ConfigDict


class PortInfo(BaseModel):
    """Information sur un port ouvert."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"port": 3000, "service": "http", "version": "Node.js Express"}
            ]
        }
    )

    port: int
    service: str
    version: str | None = None


class EndpointInfo(BaseModel):
    """Information sur un endpoint decouvert."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "path": "/rest/user/login",
                    "method": "POST",
                    "status_code": 200,
                    "auth_required": False,
                    "parameters": ["email", "password"],
                }
            ]
        }
    )

    path: str
    method: str
    status_code: int
    auth_required: bool = False
    parameters: list[str] = []


class HeaderAnalysis(BaseModel):
    """Analyse des headers de securite HTTP."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "missing_security_headers": [
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "Strict-Transport-Security",
                    ],
                    "server_info_leaked": True,
                }
            ]
        }
    )

    missing_security_headers: list[str] = []
    server_info_leaked: bool = False


class FieldInfo(BaseModel):
    """Information sur un champ de formulaire."""

    name: str
    type: str = "text"
    placeholder: str = ""


class FormInfo(BaseModel):
    """Information sur un formulaire HTML."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "endpoint": "/rest/user/login",
                    "fields": [
                        {"name": "email", "type": "email"},
                        {"name": "password", "type": "password"},
                    ],
                    "method": "POST",
                    "action": "/rest/user/login",
                    "source": "dynamic",
                }
            ]
        }
    )

    endpoint: str = ""
    fields: list[FieldInfo] = []
    method: str = "POST"
    action: str = ""
    source: str = "static"


class ScanResult(BaseModel):
    """Resultat complet d'un scan de reconnaissance."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "target": "http://localhost:3000",
                    "scan_timestamp": "2025-01-15T10:30:00Z",
                    "open_ports": [
                        {"port": 3000, "service": "http", "version": "Node.js Express"}
                    ],
                    "endpoints": [
                        {
                            "path": "/rest/user/login",
                            "method": "POST",
                            "status_code": 200,
                            "auth_required": False,
                            "parameters": ["email", "password"],
                        }
                    ],
                    "technologies": ["Node.js", "Express", "Angular", "SQLite"],
                    "headers": {
                        "missing_security_headers": ["Content-Security-Policy"],
                        "server_info_leaked": True,
                    },
                    "forms": [
                        {
                            "endpoint": "/rest/user/login",
                            "fields": ["email", "password"],
                            "method": "POST",
                        }
                    ],
                }
            ]
        }
    )

    target: str
    scan_timestamp: str
    open_ports: list[PortInfo] = []
    endpoints: list[EndpointInfo] = []
    technologies: list[str] = []
    headers: HeaderAnalysis = HeaderAnalysis()
    forms: list[FormInfo] = []
    risk_score: dict = {}

    def compute_risk_score(self) -> dict:
        """Calcule un score de risque objectif base sur les faits du scan.

        Retourne un dict avec :
        - score: 0-100 (0 = securise, 100 = critique)
        - level: "critique", "eleve", "moyen", "faible"
        - findings: liste de constats avec leur severite
        """
        findings = []
        score = 0

        # --- Headers manquants (max 20 points) ---
        critical_headers = {"Content-Security-Policy", "Strict-Transport-Security"}
        for h in self.headers.missing_security_headers:
            if h in critical_headers:
                findings.append({"severity": "eleve", "detail": f"Header critique manquant: {h}"})
                score += 8
            else:
                findings.append({"severity": "moyen", "detail": f"Header manquant: {h}"})
                score += 3

        # --- Info serveur exposee (5 points) ---
        if self.headers.server_info_leaked:
            findings.append({"severity": "moyen", "detail": "Information serveur exposee (Server/X-Powered-By)"})
            score += 5

        # --- Endpoints sans auth (max 25 points) ---
        api_no_auth = [ep for ep in self.endpoints
                       if ep.status_code == 200
                       and (ep.path.startswith("/api/") or ep.path.startswith("/rest/"))
                       and not ep.auth_required]
        if api_no_auth:
            findings.append({"severity": "eleve", "detail": f"{len(api_no_auth)} endpoint(s) API publics sans authentification"})
            score += min(len(api_no_auth) * 3, 25)

        # --- Endpoints admin accessibles (15 points) ---
        admin_eps = [ep for ep in self.endpoints
                     if ep.status_code == 200
                     and any(k in ep.path.lower() for k in ("admin", "dashboard", "manage"))]
        if admin_eps:
            findings.append({"severity": "critique", "detail": f"Interface admin accessible: {', '.join(ep.path for ep in admin_eps[:3])}"})
            score += 15

        # --- Formulaires sans protection (max 10 points) ---
        if self.forms:
            csp_missing = "Content-Security-Policy" not in [h for h in self.headers.missing_security_headers]
            if not csp_missing:  # CSP manquant
                findings.append({"severity": "eleve", "detail": f"{len(self.forms)} formulaire(s) sans CSP — risque XSS"})
                score += 10

        # --- Technologies obsoletes ou a risque (max 15 points) ---
        risky_techs = []
        for tech in self.technologies:
            tech_lower = tech.lower()
            if "sqlite" in tech_lower:
                risky_techs.append(tech)
            if "jwt" in tech_lower:
                risky_techs.append(tech)
        if risky_techs:
            findings.append({"severity": "moyen", "detail": f"Technologies a surveiller: {', '.join(risky_techs)}"})
            score += len(risky_techs) * 5

        # --- Ports non-web ouverts (max 10 points) ---
        non_web_ports = [p for p in self.open_ports if p.port not in (80, 443, 8080, 8443)]
        db_ports = [p for p in non_web_ports if p.port in (3306, 5432, 27017, 6379, 9200, 1433)]
        if db_ports:
            findings.append({"severity": "critique", "detail": f"Port(s) base de donnees expose(s): {', '.join(str(p.port) for p in db_ports)}"})
            score += len(db_ports) * 10

        # Clamp et level
        score = min(score, 100)
        if score >= 70:
            level = "critique"
        elif score >= 40:
            level = "eleve"
        elif score >= 20:
            level = "moyen"
        else:
            level = "faible"

        self.risk_score = {
            "score": score,
            "level": level,
            "findings": findings,
        }
        return self.risk_score
