"""Red-team runner.

Fires the attack corpus at a target concurrently (bounded by a semaphore),
analyzes each response, and aggregates results by OWASP category with latency,
token and cost instrumentation. Also measures the guardrail false-positive rate
over the legitimate-query set.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from statistics import mean

from loguru import logger

from ai_safety_framework.analyzers.response_analyzer import analyze
from ai_safety_framework.detectors.base import Detector
from ai_safety_framework.guardrails.layer import GuardrailsLayer
from ai_safety_framework.observability import new_trace_id
from ai_safety_framework.schemas import (
    Attack,
    AttackResult,
    CategoryStats,
    FalsePositiveReport,
    LegitQuery,
    LegitResult,
    RedTeamReport,
)
from ai_safety_framework.targets.base import Target


def _percentile(values: list[int], pct: float) -> int:
    """Nearest-rank percentile of ``values`` (0 for empty input)."""
    if not values:
        return 0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round(pct / 100.0 * (len(ordered) - 1)))))
    return ordered[k]


class RedTeamRunner:
    """Runs a corpus of attacks against one target and aggregates the outcome.

    Args:
        target: The system under test.
        guardrails: Optional guardrails applied around the target by the runner
            itself (independent of any guardrails the target embeds). When set,
            a blocked input short-circuits the attack as a refusal.
        response_detectors: Extra detectors recorded on each response.
        max_concurrency: Maximum in-flight attacks.
    """

    def __init__(
        self,
        target: Target,
        guardrails: GuardrailsLayer | None = None,
        response_detectors: list[Detector] | None = None,
        max_concurrency: int = 8,
    ) -> None:
        self.target = target
        self.guardrails = guardrails
        self.response_detectors = response_detectors or []
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def _run_one(self, attack: Attack) -> AttackResult:
        """Execute one attack (optionally guardrailed) and analyze the response."""
        trace_id = new_trace_id()
        async with self.semaphore:
            with logger.contextualize(trace_id=trace_id):
                guardrail_ms = 0
                blocked_by: list[str] = []
                redactions: list[str] = []

                if self.guardrails is not None:
                    verdict = self.guardrails.screen_input(attack.prompt)
                    guardrail_ms += verdict.latency_ms
                    if not verdict.safe:
                        blocked_by = verdict.blocked
                        logger.info("attack {} blocked at input: {}", attack.id, blocked_by)
                        return AttackResult(
                            attack_id=attack.id,
                            category=attack.category,
                            technique=attack.technique,
                            severity=attack.severity,
                            success=False,
                            outcome="refused",
                            refused=True,
                            blocked_by_guardrail=blocked_by,
                            guardrail_latency_ms=guardrail_ms,
                            trace_id=trace_id,
                        )

                reply = await self.target.respond(attack.prompt)
                response_text = reply.text
                if self.guardrails is not None:
                    out = self.guardrails.screen_output(response_text)
                    guardrail_ms += out.latency_ms
                    redactions = out.redactions
                    response_text = out.sanitized_output

                if reply.text.startswith("[target error:"):
                    return AttackResult(
                        attack_id=attack.id,
                        category=attack.category,
                        technique=attack.technique,
                        severity=attack.severity,
                        success=False,
                        outcome="error",
                        error=reply.text,
                        response_snippet=reply.text[:200],
                        latency_ms=reply.latency_ms,
                        guardrail_latency_ms=guardrail_ms,
                        trace_id=trace_id,
                    )

                analysis = analyze(attack, response_text, self.response_detectors)
                logger.info(
                    "attack {} -> {} (success={})",
                    attack.id,
                    analysis.outcome,
                    analysis.attack_success,
                )
                return AttackResult(
                    attack_id=attack.id,
                    category=attack.category,
                    technique=attack.technique,
                    severity=attack.severity,
                    success=analysis.attack_success,
                    outcome=analysis.outcome,
                    refused=analysis.refused,
                    leaked_pii=analysis.pii_found,
                    flagged_by=analysis.leaked_indicators,
                    blocked_by_guardrail=blocked_by,
                    output_redactions=redactions,
                    response_snippet=response_text[:200],
                    latency_ms=reply.latency_ms,
                    guardrail_latency_ms=guardrail_ms,
                    input_tokens=reply.input_tokens,
                    output_tokens=reply.output_tokens,
                    cost_usd=reply.cost_usd,
                    trace_id=reply.trace_id or trace_id,
                )

    async def run(self, attacks: list[Attack], run_id: str | None = None) -> RedTeamReport:
        """Run all attacks concurrently and build the aggregate report."""
        run_id = run_id or new_trace_id()[:12]
        results = await asyncio.gather(*(self._run_one(a) for a in attacks))
        return self._aggregate(run_id, list(results))

    def _aggregate(self, run_id: str, results: list[AttackResult]) -> RedTeamReport:
        """Compute per-category stats and run-level metrics."""
        by_cat_total: defaultdict[str, int] = defaultdict(int)
        by_cat_success: defaultdict[str, int] = defaultdict(int)
        by_cat_refused: defaultdict[str, int] = defaultdict(int)
        by_cat_ignored: defaultdict[str, int] = defaultdict(int)
        by_cat_error: defaultdict[str, int] = defaultdict(int)

        for r in results:
            by_cat_total[r.category] += 1
            if r.success:
                by_cat_success[r.category] += 1
            if r.outcome == "refused":
                by_cat_refused[r.category] += 1
            elif r.outcome == "ignored":
                by_cat_ignored[r.category] += 1
            elif r.outcome == "error":
                by_cat_error[r.category] += 1

        by_category: dict[str, CategoryStats] = {}
        for cat, total in sorted(by_cat_total.items()):
            by_category[cat] = CategoryStats(
                category=cat,  # type: ignore[arg-type]
                n_attacks=total,
                n_success=by_cat_success[cat],
                n_refused=by_cat_refused[cat],
                n_ignored=by_cat_ignored[cat],
                n_error=by_cat_error[cat],
                success_rate=round(by_cat_success[cat] / total, 4) if total else 0.0,
            )

        n = len(results)
        n_success = sum(1 for r in results if r.success)
        latencies = [r.latency_ms for r in results]
        guardrail_ms = [r.guardrail_latency_ms for r in results if r.guardrail_latency_ms]

        return RedTeamReport(
            run_id=run_id,
            target_name=self.target.name,
            target_mode=self.target.mode,  # type: ignore[arg-type]
            guardrails_enabled=self.guardrails is not None,
            guardrails_mode=self.guardrails.mode if self.guardrails else "none",
            n_attacks=n,
            n_success=n_success,
            success_rate=round(n_success / n, 4) if n else 0.0,
            by_category=by_category,
            results=results,
            latency_ms_total=sum(latencies),
            latency_ms_p50=_percentile(latencies, 50),
            latency_ms_p95=_percentile(latencies, 95),
            guardrail_latency_ms_mean=round(mean(guardrail_ms), 3) if guardrail_ms else 0.0,
            cost_usd_total=round(sum(r.cost_usd for r in results), 8),
            input_tokens_total=sum(r.input_tokens for r in results),
            output_tokens_total=sum(r.output_tokens for r in results),
        )

    async def measure_false_positives(
        self, queries: list[LegitQuery], run_id: str | None = None
    ) -> FalsePositiveReport:
        """Run benign queries through the guardrails and measure the FP rate.

        A false positive is a legitimate query the guardrails block at input, or
        that the target refuses. Requires guardrails to be configured.
        """
        run_id = run_id or new_trace_id()[:12]
        results = await asyncio.gather(*(self._run_legit(q) for q in queries))
        results = list(results)

        n = len(results)
        n_blocked = sum(1 for r in results if r.blocked)
        n_refused = sum(1 for r in results if r.refused_by_target)
        by_domain: dict[str, float] = {}
        domains = {r.domain for r in results}
        for d in sorted(domains):
            rows = [r for r in results if r.domain == d]
            by_domain[d] = round(sum(1 for r in rows if r.blocked) / len(rows), 4)
        tricky = [r for r in results if r.tricky]
        guardrail_ms = [r.guardrail_latency_ms for r in results if r.guardrail_latency_ms]

        return FalsePositiveReport(
            run_id=run_id,
            target_name=self.target.name,
            guardrails_mode=self.guardrails.mode if self.guardrails else "none",
            n_queries=n,
            n_blocked=n_blocked,
            fp_rate=round(n_blocked / n, 4) if n else 0.0,
            n_refused_by_target=n_refused,
            by_domain=by_domain,
            tricky_fp_rate=(
                round(sum(1 for r in tricky if r.blocked) / len(tricky), 4) if tricky else 0.0
            ),
            guardrail_latency_ms_mean=round(mean(guardrail_ms), 3) if guardrail_ms else 0.0,
            results=results,
        )

    async def _run_legit(self, query: LegitQuery) -> LegitResult:
        """Process one benign query and record whether it was wrongly blocked."""
        async with self.semaphore:
            guardrail_ms = 0
            if self.guardrails is not None:
                verdict = self.guardrails.screen_input(query.text)
                guardrail_ms += verdict.latency_ms
                if not verdict.safe:
                    return LegitResult(
                        query_id=query.id,
                        domain=query.domain,
                        tricky=query.tricky,
                        blocked=True,
                        blocked_by=verdict.blocked,
                        guardrail_latency_ms=guardrail_ms,
                    )
            reply = await self.target.respond(query.text)
            text = reply.text
            if self.guardrails is not None:
                out = self.guardrails.screen_output(text)
                guardrail_ms += out.latency_ms
                text = out.sanitized_output
            from ai_safety_framework.analyzers.response_analyzer import _is_refusal

            refused = _is_refusal(text.lower())
            return LegitResult(
                query_id=query.id,
                domain=query.domain,
                tricky=query.tricky,
                blocked=False,
                refused_by_target=refused,
                guardrail_latency_ms=guardrail_ms,
                response_snippet=text[:200],
            )
