"""Executeur d'attaques contre la cible.

Envoie les payloads aux endpoints cibles et analyse les reponses
pour determiner si l'attaque a reussi.

Seule l'attaque SQLi est implementee. Les autres types sont en TODO.

TODO: Implementer _test_xss, _test_idor, _test_path_traversal.
"""

import json
import time
from pathlib import Path

import requests

from src.infra.config import settings
from src.infra.decorators import logged, retry, timed
from src.infra.exceptions import AttackError
from src.infra.logging import get_logger
from src.models import (
    AttackPlan,
    AttackResult,
    AttackVector,
    PayloadResult,
    SingleAttackResult,
)

logger = get_logger(__name__)


class AttackExecutor:
    """Execute les attaques du plan contre la cible.

    Rate-limited selon ``settings.attack_delay`` entre chaque requete
    pour ne pas surcharger la cible.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.delay = settings.attack_delay

    @retry(max_attempts=2, base_delay=0.5, exceptions=(requests.ConnectionError, requests.Timeout))
    def _test_sqli(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Teste une injection SQL sur l'endpoint cible.

        Envoie le payload comme valeur des champs du formulaire
        et analyse la reponse pour detecter un succes.

        Args:
            vector: Vecteur d'attaque avec l'endpoint et les champs cibles.
            payload: Payload SQLi a tester.

        Returns:
            Resultat de l'attaque.
        """
        url = f"{self.base_url}{vector.target_endpoint}"
        logger.debug("[SQLI] %s <- %s", url, payload)

        # Construire le body avec le payload dans chaque champ
        body = {}
        for field in vector.target_fields:
            body[field] = payload

        try:
            resp = requests.post(url, json=body, timeout=10)
            snippet = resp.text[:200]

            # Detection de succes
            success = False
            detection = "Aucune injection detectee"

            if resp.status_code == 200 and "authentication" in resp.text.lower():
                success = True
                detection = "Token d'authentification retourne sans identifiants valides"
            elif "sqlite" in resp.text.lower() or "sql" in resp.text.lower():
                detection = "Erreur SQL exposee dans la reponse"
                if "error" not in resp.text.lower():
                    success = True

            result = SingleAttackResult(
                vector_id=vector.id,
                payload_used=payload,
                target_endpoint=vector.target_endpoint,
                http_status=resp.status_code,
                response_snippet=snippet,
                success=success,
                detection_method=detection,
            )

            status = "SUCCES" if success else "ECHEC"
            logger.debug("-> %s | %s | %s", resp.status_code, status, detection)
            return result

        except requests.RequestException as e:
            logger.error("Erreur requete SQLI: %s", e)
            return SingleAttackResult(
                vector_id=vector.id,
                payload_used=payload,
                target_endpoint=vector.target_endpoint,
                http_status=0,
                response_snippet=str(e),
                success=False,
                detection_method=f"Erreur de connexion: {e}",
            )

    def _test_xss(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Teste une attaque XSS sur l'endpoint cible.

        TODO: Implementer le test XSS.
            - Envoyer le payload dans les champs cibles via POST
            - Verifier si le payload est reflete tel quel dans la reponse
            - Verifier si le payload est stocke (GET apres POST)
            - Detecter les sanitizations partielles
        """
        raise AttackError("_test_xss n'est pas encore implemente", vector_id=vector.id)

    def _test_idor(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Teste une attaque IDOR sur l'endpoint cible.

        TODO: Implementer le test IDOR.
            - Remplacer l'ID dans l'URL par les valeurs du payload
            - Envoyer des requetes GET avec differents IDs
            - Comparer les reponses pour detecter l'acces non autorise
            - Verifier si les donnees retournees appartiennent a un autre utilisateur
        """
        raise AttackError("_test_idor n'est pas encore implemente", vector_id=vector.id)

    def _test_path_traversal(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Teste une attaque path traversal sur l'endpoint cible.

        TODO: Implementer le test path traversal.
            - Envoyer le payload (../../etc/passwd) dans les parametres
            - Verifier si la reponse contient du contenu de fichier systeme
            - Tester differentes encodages (URL encoding, double encoding)
        """
        raise AttackError("_test_path_traversal n'est pas encore implemente", vector_id=vector.id)

    @logged
    @timed
    def execute_all(self, attack_plan: AttackPlan, payload_result: PayloadResult) -> AttackResult:
        """Execute toutes les attaques du plan.

        Args:
            attack_plan: Plan d'attaque avec les vecteurs.
            payload_result: Variantes de payloads generees.

        Returns:
            Resultats de toutes les attaques.
        """
        logger.info("Execution des attaques sur %s", self.base_url)

        results: list[SingleAttackResult] = []
        total = 0
        success_count = 0

        # Indexer les payloads par vector_id
        payload_map: dict[str, list[str]] = {}
        for gp in payload_result.payloads:
            if gp.vector_id not in payload_map:
                payload_map[gp.vector_id] = []
            payload_map[gp.vector_id].append(gp.original)
            payload_map[gp.vector_id].extend(gp.variants)

        for vector in attack_plan.vectors:
            logger.info("Vecteur %s (%s)", vector.id, vector.attack_type.value)

            payloads = payload_map.get(vector.id, vector.base_payloads)
            if not payloads:
                payloads = vector.base_payloads

            for payload in payloads:
                total += 1
                time.sleep(self.delay)

                try:
                    if vector.attack_type.value == "sqli":
                        result = self._test_sqli(vector, payload)
                    elif vector.attack_type.value == "xss":
                        result = self._test_xss(vector, payload)
                    elif vector.attack_type.value == "idor":
                        result = self._test_idor(vector, payload)
                    elif vector.attack_type.value == "path_traversal":
                        result = self._test_path_traversal(vector, payload)
                    else:
                        logger.warning("Type d'attaque non supporte: %s", vector.attack_type.value)
                        continue

                    results.append(result)
                    if result.success:
                        success_count += 1

                except AttackError as e:
                    logger.warning("Attaque non implementee: %s", e)
                    break  # Passer au vecteur suivant

        logger.info("Termine: %d tentatives, %d succes", total, success_count)

        return AttackResult(
            results=results,
            total_attempts=total,
            successful_attacks=success_count,
        )

    @staticmethod
    def from_fixtures() -> AttackResult:
        """Charge le resultat depuis la fixture JSON."""
        fixture_path = (
            Path(__file__).parent.parent.parent / "data" / "fixtures" / "attack_result.json"
        )
        logger.info("Chargement de la fixture: %s", fixture_path)
        data = json.loads(fixture_path.read_text())
        result = AttackResult.model_validate(data)
        logger.info(
            "Fixture chargee: %d tentatives, %d succes",
            result.total_attempts,
            result.successful_attacks,
        )
        return result


if __name__ == "__main__":
    import sys

    from src.infra.logging import setup_logging

    setup_logging(level=settings.log_level, fmt=settings.log_format)

    if "--fixture" in sys.argv or "--fixtures" in sys.argv:
        logger.info("Mode fixture")
        result = AttackExecutor.from_fixtures()
    else:
        # Charger les fixtures pour le plan et les payloads
        data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"
        plan_data = json.loads((data_dir / "attack_plan.json").read_text())
        payload_data = json.loads((data_dir / "payload_result.json").read_text())

        plan = AttackPlan.model_validate(plan_data)
        payloads = PayloadResult.model_validate(payload_data)

        executor = AttackExecutor(settings.target_url)
        result = executor.execute_all(plan, payloads)

    logger.info("Resultats:\n%s", result.model_dump_json(indent=2))
