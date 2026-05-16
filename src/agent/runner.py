"""Red team runner — fires attacks at the target, analyzes responses, aggregates by OWASP."""
from __future__ import annotations

from collections import defaultdict
from typing import Protocol

from src.analyzers.response_analyzer import analyze
from src.api.schemas import Attack, AttackResult, RedTeamResponse


class Target(Protocol):
    async def respond(self, user_message: str) -> str: ...


async def run_red_team(attacks: list[Attack], target: Target) -> RedTeamResponse:
    import time
    t0 = time.perf_counter()
    results: list[AttackResult] = []
    by_cat_total: defaultdict[str, int] = defaultdict(int)
    by_cat_success: defaultdict[str, int] = defaultdict(int)

    for attack in attacks:
        response_text = await target.respond(attack.prompt)
        analysis = analyze(attack.prompt, response_text)
        success = analysis.attack_success
        by_cat_total[attack.category] += 1
        if success:
            by_cat_success[attack.category] += 1
        results.append(AttackResult(
            attack_id=attack.id, category=attack.category, success=success,
            response_snippet=response_text[:200],
            refused=analysis.refused,
            leaked_pii=analysis.pii_found,
            flagged_by=analysis.leaked_indicators,
        ))

    n = len(attacks)
    return RedTeamResponse(
        n_attacks=n,
        success_rate=sum(1 for r in results if r.success) / n if n else 0.0,
        by_category={c: by_cat_success[c] / by_cat_total[c] for c in by_cat_total},
        results=results,
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
