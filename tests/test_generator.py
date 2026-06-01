"""Tests du module generateur de payloads.

Verifie que les mutations offline generent des variantes valides
et que l'orchestrateur generate_variants fonctionne correctement.
"""

from src.generator.generate import generate_variants
from src.generator.offline_mutator import mutate_payload


class TestOfflineMutator:
    """Tests des mutations deterministes hors-ligne."""

    def test_sqli_mutations(self):
        """Les mutations SQLi doivent produire des variantes."""
        variants = mutate_payload("' OR 1=1--", "sqli", n_variants=5)
        assert isinstance(variants, list)
        assert len(variants) > 0
        assert all(v != "' OR 1=1--" for v in variants)

    def test_xss_mutations(self):
        """Les mutations XSS doivent produire des variantes."""
        variants = mutate_payload("<script>alert('xss')</script>", "xss", n_variants=5)
        assert isinstance(variants, list)
        assert len(variants) > 0
        assert all(v != "<script>alert('xss')</script>" for v in variants)

    def test_idor_mutations(self):
        """Les mutations IDOR doivent produire des variantes."""
        variants = mutate_payload("/rest/basket/1", "idor", n_variants=5)
        assert isinstance(variants, list)
        assert len(variants) > 0
        assert all(v != "/rest/basket/1" for v in variants)

    def test_path_traversal_mutations(self):
        """Les mutations path_traversal doivent produire des variantes."""
        variants = mutate_payload("../../etc/passwd", "path_traversal", n_variants=5)
        assert isinstance(variants, list)
        assert len(variants) > 0
        assert all(v != "../../etc/passwd" for v in variants)

    def test_unknown_type_uses_generic(self):
        """Un type inconnu doit utiliser les mutations generiques."""
        variants = mutate_payload("test_payload", "unknown_type", n_variants=3)
        assert isinstance(variants, list)
        assert len(variants) > 0

    def test_variants_are_unique(self):
        """Les variantes ne doivent pas contenir de doublons."""
        variants = mutate_payload("' OR 1=1--", "sqli", n_variants=10)
        assert len(variants) == len(set(variants))

    def test_n_variants_respected(self):
        """Le nombre de variantes demandees doit etre respecte (ou moins si pas assez)."""
        variants = mutate_payload("' OR 1=1--", "sqli", n_variants=3)
        assert len(variants) <= 3


class TestGenerateVariants:
    """Tests de la fonction orchestratrice generate_variants."""

    def test_generate_returns_list(self):
        """generate_variants doit retourner une liste."""
        variants = generate_variants("' OR 1=1--", attack_type="sqli", n_variants=3)
        assert isinstance(variants, list)

    def test_variants_differ_from_base(self):
        """Les variantes doivent etre differentes du payload de base."""
        base = "' OR 1=1--"
        variants = generate_variants(base, attack_type="sqli", n_variants=5)
        for v in variants:
            assert v != base, f"Variante identique au base: {v}"

    def test_generate_with_attack_type(self):
        """generate_variants doit accepter un attack_type."""
        variants = generate_variants("<script>alert(1)</script>", attack_type="xss", n_variants=3)
        assert isinstance(variants, list)
        assert len(variants) > 0
