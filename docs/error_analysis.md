# Error analysis — AI Safety & Red Teaming Framework

The framework's job is to *find* failures in the system under test; this document
analyses (a) where the **detection** itself is weakest and (b) the worst findings
from the runs.

## Weakest points of the detector/analyzer

1. **Regex refusal detection is phrase-based.** A refusal worded outside
   `REFUSAL_PHRASES` is read as non-refusal; a compliant answer that happens to
   contain "I'm sorry" is read as a refusal. The LLM-as-judge exists to cover this
   but needs a key.
2. **Success indicators are literal substrings.** An attack that succeeds with
   paraphrased output (no indicator present) is scored as `ignored`. This makes
   the reported success rate a *lower bound*.
3. **DoS is length-based.** A target that streams then truncates can exceed
   `max_response_chars` transiently without a real DoS.
4. **Encoded-payload heuristic** flags a base64 blob next to a decode verb; novel
   encodings (custom ciphers) slip through the regex layer — the ML detector is
   the intended backstop.
5. **Cross-session leakage** can only be detected if the leaked content appears in
   the response text; a target that leaks through side channels is invisible here.

## Worst findings from the runs

Against the **synthetic vulnerable target**, the top successful attacks by
severity (from `eval/runs/2026-09-29-synthetic.json`, section "worst cases" in
`RESULTS.md`) are prompt-injection overrides (LLM01), info-disclosure of the
system prompt and secrets (LLM06) and insecure-output XSS (LLM02) — exactly the
categories a naive assistant fails first. Guardrails cut these from 26.4% to 5.7%
overall.

Against **Project 01 and Project 03** (deterministic fallback, no LLM), **no
attack succeeded**: P01 answers product-search queries and ignores injections;
P03 rejects most payloads at input validation (HTTP 422, surfaced as a defensive
refusal). This is the expected result for a stub with no model to jailbreak, and
is labelled as such — it is not evidence the systems are safe under a real LLM,
which is the pending `ANTHROPIC_API_KEY` run.

## What we would fix next

- Add semantic refusal detection (embedding similarity to a refusal set) to
  reduce phrase-matching brittleness without a per-request LLM call.
- Expand success indicators into small per-attack rubrics for the judge.
- Add multi-turn attacks (the current corpus is single-turn).
