# Data schema — AI Safety & Red Teaming Framework

## Built-in attack corpus (`ai_safety_framework.attacks.corpus.load_corpus`)

Each `Attack` (see `schemas.py`):

| Field | Type | Description |
|---|---|---|
| `id` | str | Stable id, `<CATEGORY>-<NNN>` |
| `category` | enum | One of the 10 OWASP LLM categories (`LLM01_…`–`LLM10_…`) |
| `name` | str | Short title |
| `technique` | str | Attack technique (`direct_override`, `base64`, `pii_fishing`, …) |
| `prompt` | str | Text sent to the target (≤ 8000 chars) |
| `expected` | enum | Safe behaviour: `refuse` or `ignore_or_refuse` |
| `success_indicators` | list[str] | Substrings a complying (vulnerable) system emits — **hand-written ground truth** |
| `max_response_chars` | int? | For DoS probes: a longer response counts as success |
| `severity` | enum | `critical` / `high` / `medium` / `low` |
| `source` | enum | `own` / `harmbench` / `jailbreakbench` / `generated` / `variant` |
| `ground_truth` | str | Provenance of the labels |

106 attacks, 10 categories (LLM01 ×14, LLM06 ×12, others ×10). Ground truth is
hand-written by the author and marked as such.

## Legitimate query set (`load_legit_queries`)

100 benign queries (`LegitQuery`: `id`, `text`, `domain` ∈ {ecommerce, sales,
general}, `tricky`) used to measure the guardrail false-positive rate. 15 are
`tricky` (contain words naive blocklists confuse with attacks, e.g. "ignore the
out-of-stock items", "drop a table setting").

## External corpora (`scripts/download_data.py`)

| Source | URL | License | Records |
|---|---|---|---|
| HarmBench behaviors | raw.githubusercontent.com/centerforaisafety/HarmBench | MIT | 400 |
| JailbreakBench PAIR artifact | raw.githubusercontent.com/JailbreakBench/artifacts | MIT | 100 |

The script records SHA-256, size and license of each download in
`data/MANIFEST.txt`, saves the license texts under `data/licenses/`, and writes an
OWASP-mapped labelled sample to `data/external_sample.json`. Raw downloads land in
`data/raw/` (gitignored). The HarmBench→OWASP mapping is documented in the script.

## Run documents (`eval/runs/*.json`)

Each scenario document holds: `scenario`, `target_label`, `sut_note`,
`llm_status`, a `baseline` and `guardrailed` `RedTeamReport`, an `fp_report`
(`FalsePositiveReport`), an `ablation` map (config → success rate) and
`worst_cases`. Reports carry per-category `CategoryStats`, per-attack
`AttackResult` (with `trace_id`, latency, tokens, `cost_usd`), and run-level
latency percentiles.

## Reproducibility

- `python -m eval.run` regenerates the runs and `eval/RESULTS.md`.
- `python scripts/download_data.py` re-downloads the external corpora and manifest.
- Random seed `20260516` is fixed in `tests/conftest.py`.
