"""Bake the static demo payload (``demo/predictions.json``).

Merges the attack corpus metadata with the pre-computed results of the run
against Project 01 (and the synthetic run, which exhibits successful attacks) into
a self-contained JSON the static gallery renders with no backend.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ai_safety_framework.attacks.corpus import load_corpus

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = REPO_ROOT / "eval" / "runs"
DEMO_JSON = REPO_ROOT / "demo" / "predictions.json"

_OWASP_TITLES = {
    "LLM01_prompt_injection": "LLM01 Prompt Injection",
    "LLM02_insecure_output": "LLM02 Insecure Output",
    "LLM03_training_poison": "LLM03 Training Data Poisoning",
    "LLM04_model_dos": "LLM04 Model DoS",
    "LLM05_supply_chain": "LLM05 Supply Chain",
    "LLM06_info_disclosure": "LLM06 Info Disclosure",
    "LLM07_insecure_plugin": "LLM07 Insecure Plugin Design",
    "LLM08_excessive_agency": "LLM08 Excessive Agency",
    "LLM09_overreliance": "LLM09 Overreliance",
    "LLM10_model_theft": "LLM10 Model Theft",
}


def _load_run(name: str) -> dict[str, Any]:
    """Load the newest saved scenario whose filename contains ``name``."""
    matches = sorted(RUNS_DIR.glob(f"*-{name}.json"))
    if not matches:
        raise FileNotFoundError(f"no eval run found for {name}; run `python -m eval.run` first")
    return json.loads(matches[-1].read_text())


def _index_results(run: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    """Index one report's attack results by attack id."""
    return {r["attack_id"]: r for r in run[key]["results"]}


def bake(gallery_size: int = 50) -> dict[str, Any]:
    """Build the demo payload from the P01 and synthetic runs."""
    p01 = _load_run("p01-chat")
    synthetic = _load_run("synthetic")
    attacks = {a.id: a for a in load_corpus()}

    p01_base = _index_results(p01, "baseline")
    p01_guard = _index_results(p01, "guardrailed")
    syn_base = _index_results(synthetic, "baseline")
    syn_guard = _index_results(synthetic, "guardrailed")

    gallery: list[dict[str, Any]] = []
    for aid, attack in list(attacks.items())[:gallery_size]:
        base = p01_base.get(aid, {})
        guard = p01_guard.get(aid, {})
        gallery.append(
            {
                "id": aid,
                "category": attack.category,
                "category_label": _OWASP_TITLES[attack.category],
                "name": attack.name,
                "technique": attack.technique,
                "severity": attack.severity,
                "prompt": attack.prompt[:240],
                "target_outcome": base.get("outcome", "n/a"),
                "target_success": bool(base.get("success", False)),
                "guardrail_outcome": guard.get("outcome", "n/a"),
                "guardrail_blocked": bool(guard.get("blocked_by_guardrail")),
                "response_snippet": base.get("response_snippet", "")[:180],
                "synthetic_success": bool(syn_base.get(aid, {}).get("success", False)),
                "synthetic_guarded_success": bool(syn_guard.get(aid, {}).get("success", False)),
            }
        )

    return {
        "project": "ai-safety-redteam",
        "generated_from": {
            "p01_run": p01["baseline"]["run_id"],
            "synthetic_run": synthetic["baseline"]["run_id"],
        },
        "note": (
            "Pre-computed from the run against Project 01 (deterministic fallback, no LLM). "
            "The synthetic columns show the same attacks against a deliberately-vulnerable "
            "target to illustrate the framework detecting real vulnerabilities."
        ),
        "summary": {
            "p01_baseline_success_rate": p01["baseline"]["success_rate"],
            "p01_guarded_success_rate": p01["guardrailed"]["success_rate"],
            "p01_fp_rate": p01["fp_report"]["fp_rate"],
            "synthetic_baseline_success_rate": synthetic["baseline"]["success_rate"],
            "synthetic_guarded_success_rate": synthetic["guardrailed"]["success_rate"],
            "synthetic_reduction": round(
                synthetic["baseline"]["success_rate"] - synthetic["guardrailed"]["success_rate"], 4
            ),
            "n_attacks_total": len(attacks),
            "n_categories": 10,
        },
        "gallery": gallery,
    }


def main() -> None:
    """Write ``demo/predictions.json``."""
    payload = bake()
    DEMO_JSON.parent.mkdir(parents=True, exist_ok=True)
    DEMO_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"wrote {DEMO_JSON} ({len(payload['gallery'])} gallery items)")


if __name__ == "__main__":
    main()
