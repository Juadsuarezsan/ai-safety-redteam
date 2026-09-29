"""PDF security report generation with reportlab.

Turns a baseline/guardrailed pair of :class:`RedTeamReport` plus a
:class:`FalsePositiveReport` into an auditable PDF: executive summary, per-OWASP
category table, severity breakdown and the worst findings.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ai_safety_framework.schemas import (
    OWASP_CATEGORIES,
    FalsePositiveReport,
    RedTeamReport,
)

_OWASP_TITLES = {
    "LLM01_prompt_injection": "LLM01 Prompt Injection",
    "LLM02_insecure_output": "LLM02 Insecure Output Handling",
    "LLM03_training_poison": "LLM03 Training Data Poisoning",
    "LLM04_model_dos": "LLM04 Model Denial of Service",
    "LLM05_supply_chain": "LLM05 Supply Chain Vulnerabilities",
    "LLM06_info_disclosure": "LLM06 Sensitive Information Disclosure",
    "LLM07_insecure_plugin": "LLM07 Insecure Plugin Design",
    "LLM08_excessive_agency": "LLM08 Excessive Agency",
    "LLM09_overreliance": "LLM09 Overreliance",
    "LLM10_model_theft": "LLM10 Model Theft",
}

_ACCENT = colors.HexColor("#7c5cff")
_DARK = colors.HexColor("#12141c")


def _pct(x: float) -> str:
    """Format a 0-1 fraction as a percentage string."""
    return f"{x * 100:.1f}%"


def generate_pdf_report(
    baseline: RedTeamReport,
    guardrailed: RedTeamReport,
    fp_report: FalsePositiveReport,
    output_path: str,
    target_label: str,
    system_under_test_note: str,
) -> Path:
    """Render a security report PDF and return its path.

    Args:
        baseline: Run without guardrails.
        guardrailed: Run with guardrails on the same corpus.
        fp_report: Guardrail false-positive measurement.
        output_path: Where to write the PDF.
        target_label: Human name of the system tested (e.g. "Project 01").
        system_under_test_note: Provenance line (e.g. deterministic fallback, no LLM).
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(out), pagesize=LETTER, topMargin=0.7 * inch, bottomMargin=0.7 * inch
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], textColor=_DARK, fontSize=20)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=_ACCENT)
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=colors.grey)

    story: list[object] = []
    story.append(Paragraph("AI Safety &amp; Red Teaming — Security Report", h1))
    story.append(Paragraph(f"Target: {target_label}", h2))
    story.append(
        Paragraph(
            f"Generated {datetime.now(UTC):%Y-%m-%d %H:%M UTC} · "
            f"OWASP LLM Top 10 · corpus of {baseline.n_attacks} attacks",
            small,
        )
    )
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<i>{system_under_test_note}</i>", small))
    story.append(Spacer(1, 14))

    reduction = baseline.success_rate - guardrailed.success_rate
    story.append(Paragraph("Executive summary", h2))
    summary_rows = [
        ["Metric", "Value"],
        ["Attack success rate (baseline)", _pct(baseline.success_rate)],
        ["Attack success rate (with guardrails)", _pct(guardrailed.success_rate)],
        ["Absolute reduction", _pct(reduction)],
        ["Guardrail false-positive rate", _pct(fp_report.fp_rate)],
        ["Mean guardrail latency", f"{guardrailed.guardrail_latency_ms_mean:.2f} ms"],
        ["Attacks executed", str(baseline.n_attacks)],
        ["Legitimate queries tested", str(fp_report.n_queries)],
    ]
    story.append(_styled_table(summary_rows, [3.2 * inch, 2.3 * inch]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Attack success by OWASP category", h2))
    cat_rows = [["OWASP category", "Baseline", "Guardrails", "FP rate (domain)"]]
    for cat in OWASP_CATEGORIES:
        b = baseline.by_category.get(cat)
        g = guardrailed.by_category.get(cat)
        cat_rows.append(
            [
                _OWASP_TITLES[cat],
                _pct(b.success_rate) if b else "n/a",
                _pct(g.success_rate) if g else "n/a",
                _pct(fp_report.fp_rate),
            ]
        )
    story.append(_styled_table(cat_rows, [2.9 * inch, 0.9 * inch, 0.9 * inch, 1.1 * inch]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Top findings (successful attacks, by severity)", h2))
    findings = sorted(
        [r for r in baseline.results if r.success],
        key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}[r.severity],
    )[:10]
    if findings:
        find_rows = [["Attack", "Category", "Severity", "Technique"]]
        for r in findings:
            find_rows.append([r.attack_id, r.category.split("_")[0], r.severity, r.technique])
        story.append(_styled_table(find_rows, [1.3 * inch, 1.2 * inch, 1.2 * inch, 2.0 * inch]))
    else:
        story.append(Paragraph("No attacks succeeded against the baseline target.", body))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Methodology", h2))
    story.append(
        Paragraph(
            "Each attack is fired at the target, the response is analysed for refusal, "
            "compliance markers, PII leakage and denial-of-service, and mapped to its OWASP "
            "category. Guardrails screen inputs (injection/jailbreak patterns) and sanitise "
            "outputs (PII redaction, HTML neutralisation). Ground truth for every attack is "
            "hand-written. False-positive rate is measured over a benign query set.",
            body,
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            f"Run IDs: baseline={baseline.run_id}, guardrailed={guardrailed.run_id}, "
            f"fp={fp_report.run_id}.",
            small,
        )
    )

    doc.build(story)
    return out


def _styled_table(rows: list[list[str]], col_widths: list[float]) -> Table:
    """Build a themed reportlab table from string rows."""
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f0ff")]),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9d9e3")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table
