"""Tests for the red-team runner: aggregation, reduction and FP measurement."""

from __future__ import annotations

from ai_safety_framework.attacks.corpus import load_corpus, load_legit_queries
from ai_safety_framework.guardrails.layer import default_layer
from ai_safety_framework.redteam.runner import RedTeamRunner, _percentile
from ai_safety_framework.targets.synthetic import GuardrailedTarget, VulnerableTarget


def test_percentile_edges() -> None:
    assert _percentile([], 50) == 0
    assert _percentile([5], 95) == 5
    assert _percentile([1, 2, 3, 4], 50) in {2, 3}


async def test_runner_aggregates_by_category() -> None:
    report = await RedTeamRunner(VulnerableTarget()).run(load_corpus())
    assert report.n_attacks == len(load_corpus())
    assert len(report.by_category) == 10
    assert 0.0 <= report.success_rate <= 1.0
    assert sum(c.n_attacks for c in report.by_category.values()) == report.n_attacks


async def test_guardrails_reduce_success_rate() -> None:
    attacks = load_corpus()
    vuln = await RedTeamRunner(VulnerableTarget()).run(attacks)
    guarded = await RedTeamRunner(GuardrailedTarget()).run(attacks)
    assert guarded.success_rate < vuln.success_rate


async def test_runner_input_guardrail_blocks_and_marks_refused() -> None:
    runner = RedTeamRunner(VulnerableTarget(), guardrails=default_layer())
    report = await runner.run(load_corpus())
    assert any(r.blocked_by_guardrail for r in report.results)
    blocked = [r for r in report.results if r.blocked_by_guardrail]
    assert all(r.outcome == "refused" for r in blocked)


async def test_false_positive_rate_low_on_benign_queries() -> None:
    runner = RedTeamRunner(VulnerableTarget(), guardrails=default_layer())
    fp = await runner.measure_false_positives(load_legit_queries())
    assert fp.n_queries == len(load_legit_queries())
    assert fp.fp_rate <= 0.15
    assert set(fp.by_domain) >= {"ecommerce", "sales", "general"}
