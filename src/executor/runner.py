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

from src.models import (
    AttackPlan,
    AttackResult,
    AttackVector,
    PayloadResult,
    SingleAttackResult,
)


class AttackExecutor:
    """Execute les attaques du plan contre la cible.

    Rate-limited a 0.2s entre chaque requete pour ne pas surcharger la cible.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.delay = 0.2  # Secondes entre chaque requete

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
        print(f"  [SQLI] {url} <- {payload}")

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
            print(f"    -> {resp.status_code} | {status} | {detection}")
            return result

        except requests.RequestException as e:
            print(f"    -> ERREUR: {e}")
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
        raise NotImplementedError("_test_xss n'est pas encore implemente")

    def _test_idor(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Teste une attaque IDOR sur l'endpoint cible.

        TODO: Implementer le test IDOR.
            - Remplacer l'ID dans l'URL par les valeurs du payload
            - Envoyer des requetes GET avec differents IDs
            - Comparer les reponses pour detecter l'acces non autorise
            - Verifier si les donnees retournees appartiennent a un autre utilisateur
        """
        raise NotImplementedError("_test_idor n'est pas encore implemente")

    def _test_path_traversal(
        self, vector: AttackVector, payload: str
    ) -> SingleAttackResult:
        """Teste une attaque path traversal sur l'endpoint cible.

        TODO: Implementer le test path traversal.
            - Envoyer le payload (../../etc/passwd) dans les parametres
            - Verifier si la reponse contient du contenu de fichier systeme
            - Tester differentes encodages (URL encoding, double encoding)
        """
        raise NotImplementedError("_test_path_traversal n'est pas encore implemente")

    def execute_all(
        self, attack_plan: AttackPlan, payload_result: PayloadResult
    ) -> AttackResult:
        """Execute toutes les attaques du plan.

        Args:
            attack_plan: Plan d'attaque avec les vecteurs.
            payload_result: Variantes de payloads generees.

        Returns:
            Resultats de toutes les attaques.
        """
        print(f"\n{'='*60}")
        print(f"[EXECUTOR] Execution des attaques sur {self.base_url}")
        print(f"{'='*60}")

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
            print(f"\n--- Vecteur {vector.id} ({vector.attack_type.value}) ---")

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
                        print(f"  [SKIP] Type d'attaque non supporte: {vector.attack_type.value}")
                        continue

                    results.append(result)
                    if result.success:
                        success_count += 1

                except NotImplementedError as e:
                    print(f"  [SKIP] {e}")
                    break  # Passer au vecteur suivant

        print(f"\n{'='*60}")
        print(f"[EXECUTOR] Terminé: {total} tentatives, {success_count} succes")
        print(f"{'='*60}")

        return AttackResult(
            results=results,
            total_attempts=total,
            successful_attacks=success_count,
        )

    @staticmethod
    def from_fixtures() -> AttackResult:
        """Charge le resultat depuis la fixture JSON."""
        fixture_path = (
            Path(__file__).parent.parent.parent
            / "data"
            / "fixtures"
            / "attack_result.json"
        )
        print(f"[EXECUTOR] Chargement de la fixture: {fixture_path}")
        data = json.loads(fixture_path.read_text())
        result = AttackResult.model_validate(data)
        print(
            f"[EXECUTOR] Fixture chargee: {result.total_attempts} tentatives, "
            f"{result.successful_attacks} succes"
        )
        return result


if __name__ == "__main__":
    import sys

    if "--fixture" in sys.argv or "--fixtures" in sys.argv:
        print("=== Mode fixture ===")
        result = AttackExecutor.from_fixtures()
    else:
        # Charger les fixtures pour le plan et les payloads
        data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"
        plan_data = json.loads((data_dir / "attack_plan.json").read_text())
        payload_data = json.loads((data_dir / "payload_result.json").read_text())

        plan = AttackPlan.model_validate(plan_data)
        payloads = PayloadResult.model_validate(payload_data)

        executor = AttackExecutor("http://localhost:3000")
        result = executor.execute_all(plan, payloads)

    print("\n=== Resultats ===")
    print(result.model_dump_json(indent=2))
