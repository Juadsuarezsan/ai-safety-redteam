"""Evaluation entry point: ``python -m eval.run``.

Runs one scenario (synthetic or a live HTTP target), saves the full result under
``eval/runs/<date>-<name>.json``, persists it to the run store, and regenerates
``eval/RESULTS.md`` from every saved run so the table is always reproducible.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from ai_safety_framework.attacks.corpus import load_corpus, load_legit_queries
from ai_safety_framework.config import get_settings
from ai_safety_framework.guardrails.layer import default_layer
from ai_safety_framework.observability import configure_logging
from ai_safety_framework.redteam.runner import RedTeamRunner
from ai_safety_framework.schemas import FalsePositiveReport, RedTeamReport
from ai_safety_framework.storage.repository import get_repository
from ai_safety_framework.targets.base import Target
from ai_safety_framework.targets.http_target import HttpTarget
from ai_safety_framework.targets.synthetic import GuardrailedTarget, VulnerableTarget
from eval.metrics import ablation_layers, load_scenarios, render_results_md, worst_cases

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = REPO_ROOT / "eval" / "runs"
RESULTS_MD = REPO_ROOT / "eval" / "RESULTS.md"


async def _ablation(
    target_factory: callable[[], Target], attacks: list, max_conc: int
) -> dict[str, float]:
    """Run the guardrail-configuration ablation, returning success rate per config."""
    out: dict[str, float] = {}
    for name, layer in ablation_layers().items():
        runner = RedTeamRunner(target_factory(), guardrails=layer, max_concurrency=max_conc)
        report = await runner.run(attacks, run_id=f"abl-{name}")
        out[name] = report.success_rate
    return out


async def run_synthetic(max_conc: int) -> dict:
    """Scenario: synthetic vulnerable target with/without guardrails."""
    attacks = load_corpus()
    legit = load_legit_queries()

    baseline = await RedTeamRunner(VulnerableTarget(), max_concurrency=max_conc).run(
        attacks, run_id="synthetic-baseline"
    )
    guardrailed = await RedTeamRunner(GuardrailedTarget(), max_concurrency=max_conc).run(
        attacks, run_id="synthetic-guardrailed"
    )
    fp = await RedTeamRunner(
        VulnerableTarget(), guardrails=default_layer(), max_concurrency=max_conc
    ).measure_false_positives(legit, run_id="synthetic-fp")
    ablation = await _ablation(VulnerableTarget, attacks, max_conc)

    return _scenario_doc(
        scenario="Synthetic target",
        target_label="deliberately-vulnerable in-repo assistant",
        sut_note=(
            "Synthetic target with wired-in vulnerable responses; proves the corpus, "
            "analyzer and guardrails end to end. Not a real system."
        ),
        baseline=baseline,
        guardrailed=guardrailed,
        fp=fp,
        ablation=ablation,
        llm_status="n/a (synthetic target)",
    )


async def run_http(url: str, adapter: str, label: str, max_conc: int) -> dict:
    """Scenario: a live HTTP target; our guardrails wrap it to measure reduction."""
    attacks = load_corpus()
    legit = load_legit_queries()
    settings = get_settings()

    def make() -> HttpTarget:
        return HttpTarget(
            base_url=url,
            adapter=adapter,
            timeout_s=settings.target_timeout_s,
            max_retries=settings.target_max_retries,
            name=label,
        )

    base_target = make()
    baseline = await RedTeamRunner(base_target, max_concurrency=max_conc).run(
        attacks, run_id=f"{adapter}-baseline"
    )
    await base_target.aclose()

    guard_target = make()
    guardrailed = await RedTeamRunner(
        guard_target, guardrails=default_layer(), max_concurrency=max_conc
    ).run(attacks, run_id=f"{adapter}-guardrailed")
    await guard_target.aclose()

    fp_target = make()
    fp = await RedTeamRunner(
        fp_target, guardrails=default_layer(), max_concurrency=max_conc
    ).measure_false_positives(legit, run_id=f"{adapter}-fp")
    await fp_target.aclose()

    targets_for_ablation: list[HttpTarget] = []

    def make_tracked() -> HttpTarget:
        t = make()
        targets_for_ablation.append(t)
        return t

    ablation = await _ablation(make_tracked, attacks, max_conc)
    for t in targets_for_ablation:
        await t.aclose()

    return _scenario_doc(
        scenario=f"HTTP target ({adapter})",
        target_label=label,
        sut_note=(
            "Live HTTP run against the real system started locally, but the target had "
            "no LLM configured (llm_enabled=false): it answered with its deterministic "
            "fallback. This measures the framework and the guardrail reduction, not the "
            "target's quality under a real model."
        ),
        baseline=baseline,
        guardrailed=guardrailed,
        fp=fp,
        ablation=ablation,
        llm_status="pendiente (requiere ANTHROPIC_API_KEY en el sistema bajo prueba)",
    )


def _scenario_doc(
    scenario: str,
    target_label: str,
    sut_note: str,
    baseline: RedTeamReport,
    guardrailed: RedTeamReport,
    fp: FalsePositiveReport,
    ablation: dict[str, float],
    llm_status: str,
) -> dict:
    """Assemble the serialisable scenario document written to eval/runs/."""
    return {
        "scenario": scenario,
        "target_label": target_label,
        "sut_note": sut_note,
        "generated_at": datetime.now(UTC).isoformat(),
        "llm_status": llm_status,
        "baseline": baseline.model_dump(mode="json"),
        "guardrailed": guardrailed.model_dump(mode="json"),
        "fp_report": fp.model_dump(mode="json"),
        "ablation": ablation,
        "worst_cases": [w.model_dump(mode="json") for w in worst_cases(baseline)],
    }


def _save_scenario(doc: dict, name: str) -> Path:
    """Write the scenario document and persist its reports to the run store."""
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    date = datetime.now(UTC).strftime("%Y-%m-%d")
    path = RUNS_DIR / f"{date}-{name}.json"
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    logger.info("wrote {}", path)

    settings = get_settings()
    repo = get_repository(settings.database_url, settings.sqlite_path)
    repo.save(RedTeamReport.model_validate(doc["baseline"]))
    repo.save(RedTeamReport.model_validate(doc["guardrailed"]))
    return path


def _regenerate_results() -> None:
    """Rebuild eval/RESULTS.md from every saved scenario."""
    scenarios = load_scenarios(RUNS_DIR)
    RESULTS_MD.write_text(render_results_md(scenarios))
    logger.info("regenerated {} from {} scenario(s)", RESULTS_MD, len(scenarios))


def main() -> None:
    """CLI entry point for the evaluation harness."""
    parser = argparse.ArgumentParser(description="Run a red-team evaluation scenario.")
    parser.add_argument("--target", choices=["synthetic", "http"], default="synthetic")
    parser.add_argument("--url", default=None, help="Base URL for the HTTP target")
    parser.add_argument("--adapter", default="chat", help="HTTP adapter: chat|research")
    parser.add_argument("--label", default=None, help="Human label for the target")
    parser.add_argument("--name", default=None, help="Run file name suffix")
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--results-only", action="store_true", help="Only regenerate RESULTS.md")
    args = parser.parse_args()

    settings = get_settings()
    configure_logging(settings.log_level)
    max_conc = args.concurrency or settings.max_concurrency

    if args.results_only:
        _regenerate_results()
        return

    if args.target == "synthetic":
        doc = asyncio.run(run_synthetic(max_conc))
        name = args.name or "synthetic"
    else:
        if not args.url:
            parser.error("--url is required for --target http")
        label = args.label or f"{args.adapter}@{args.url}"
        doc = asyncio.run(run_http(args.url, args.adapter, label, max_conc))
        name = args.name or f"http-{args.adapter}"

    _save_scenario(doc, name)
    _regenerate_results()
    print(
        f"scenario={doc['scenario']} baseline={doc['baseline']['success_rate']:.3f} "
        f"guardrailed={doc['guardrailed']['success_rate']:.3f} "
        f"fp={doc['fp_report']['fp_rate']:.3f}"
    )


if __name__ == "__main__":
    main()
