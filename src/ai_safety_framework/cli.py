"""Command-line interface: ``ai-safety-redteam``.

Subcommands:
    scan     — run the corpus against a live HTTP target, print the summary
    report   — build a PDF security report from a saved eval scenario JSON
    corpus   — print corpus statistics
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from ai_safety_framework.attacks.corpus import load_corpus, load_legit_queries
from ai_safety_framework.config import get_settings
from ai_safety_framework.guardrails.layer import default_layer
from ai_safety_framework.observability import configure_logging
from ai_safety_framework.redteam.runner import RedTeamRunner
from ai_safety_framework.reports.pdf import generate_pdf_report
from ai_safety_framework.schemas import FalsePositiveReport, RedTeamReport
from ai_safety_framework.targets.http_target import HttpTarget


async def _scan(url: str, adapter: str, guardrails: bool) -> None:
    """Run the corpus against a live HTTP target and print the summary."""
    settings = get_settings()
    target = HttpTarget(base_url=url, adapter=adapter, timeout_s=settings.target_timeout_s)
    try:
        layer = default_layer() if guardrails else None
        runner = RedTeamRunner(target, guardrails=layer, max_concurrency=settings.max_concurrency)
        report = await runner.run(load_corpus())
    finally:
        await target.aclose()
    print(f"target={report.target_name}")
    print(f"attacks={report.n_attacks} success_rate={report.success_rate:.3f}")
    for cat, stats in sorted(report.by_category.items()):
        print(f"  {cat}: {stats.success_rate:.3f} ({stats.n_success}/{stats.n_attacks})")


def _report(scenario_path: str, output_path: str) -> None:
    """Render a PDF report from a saved eval scenario document."""
    doc = json.loads(Path(scenario_path).read_text())
    generate_pdf_report(
        baseline=RedTeamReport.model_validate(doc["baseline"]),
        guardrailed=RedTeamReport.model_validate(doc["guardrailed"]),
        fp_report=FalsePositiveReport.model_validate(doc["fp_report"]),
        output_path=output_path,
        target_label=doc["target_label"],
        system_under_test_note=doc["sut_note"],
    )
    print(f"wrote {output_path}")


def _corpus() -> None:
    """Print corpus and legitimate-query statistics."""
    attacks = load_corpus()
    legit = load_legit_queries()
    from collections import Counter

    counts = Counter(a.category for a in attacks)
    print(f"attacks: {len(attacks)} across {len(counts)} OWASP categories")
    for cat, n in sorted(counts.items()):
        print(f"  {cat}: {n}")
    print(f"legit queries: {len(legit)} (tricky: {sum(q.tricky for q in legit)})")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``ai-safety-redteam`` console script."""
    configure_logging(get_settings().log_level)
    parser = argparse.ArgumentParser(prog="ai-safety-redteam")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a live HTTP target")
    p_scan.add_argument("--url", required=True)
    p_scan.add_argument("--adapter", default="chat")
    p_scan.add_argument("--no-guardrails", action="store_true")

    p_report = sub.add_parser("report", help="build a PDF from a saved scenario JSON")
    p_report.add_argument("scenario")
    p_report.add_argument("-o", "--output", required=True)

    sub.add_parser("corpus", help="print corpus statistics")

    args = parser.parse_args(argv)
    if args.command == "scan":
        asyncio.run(_scan(args.url, args.adapter, not args.no_guardrails))
    elif args.command == "report":
        _report(args.scenario, args.output)
    elif args.command == "corpus":
        _corpus()
    return 0


if __name__ == "__main__":
    sys.exit(main())
