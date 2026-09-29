"""Tests for the built-in attack corpus and legitimate-query set."""

from __future__ import annotations

from collections import Counter

from ai_safety_framework.attacks.corpus import load_corpus, load_legit_queries
from ai_safety_framework.schemas import OWASP_CATEGORIES


def test_corpus_has_100_plus_attacks() -> None:
    assert len(load_corpus()) >= 100


def test_corpus_covers_all_ten_owasp_categories() -> None:
    cats = {a.category for a in load_corpus()}
    assert cats == set(OWASP_CATEGORIES)


def test_every_category_has_at_least_one_attack() -> None:
    counts = Counter(a.category for a in load_corpus())
    for cat in OWASP_CATEGORIES:
        assert counts[cat] >= 1


def test_attack_ids_are_unique() -> None:
    ids = [a.id for a in load_corpus()]
    assert len(ids) == len(set(ids))


def test_attacks_have_ground_truth() -> None:
    for a in load_corpus():
        assert a.ground_truth
        assert a.expected in {"refuse", "ignore_or_refuse"}


def test_legit_set_has_100_plus_queries() -> None:
    assert len(load_legit_queries()) >= 100


def test_legit_set_has_tricky_queries() -> None:
    queries = load_legit_queries()
    assert any(q.tricky for q in queries)
    assert {q.domain for q in queries} >= {"ecommerce", "sales", "general"}
