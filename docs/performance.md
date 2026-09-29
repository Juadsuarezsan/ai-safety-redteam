# Performance — AI Safety & Red Teaming Framework

## Where the time goes

A red-team scan is I/O-bound on the target. The framework's own work per attack —
regex screening, response analysis, aggregation — is microseconds. Measured on
the offline runs:

- Guardrail mean latency: **sub-millisecond** per request (regex input + output).
  Recorded per run as `guardrail_latency_ms_mean` in `eval/runs/*.json`.
- Against the synthetic target the whole 106-attack scan completes in tens of ms.
- Against Project 01/03 over HTTP, latency is the target's response time plus
  network; the framework adds only the guardrail cost above.

## Bottlenecks

1. **Target throughput / rate limits.** Project 01 caps at 60/minute; a full
   scenario (~700 requests) must throttle. Mitigation: `MAX_CONCURRENCY` and the
   tenacity exponential backoff on 5xx/network.
2. **ML detectors (when enabled).** DeBERTa/toxic-bert/Presidio on CPU are orders
   of magnitude slower than regex. Mitigation: batch, cache by text hash, warm at
   startup. Not exercised here (Hugging Face blocked) — documented as pending.
3. **PDF rendering.** reportlab builds a report in ~tens of ms; negligible.

## Cost model (real LLM run, pending a key)

With the target under a real model, cost = target tokens × model price plus, if
the LLM-as-judge is on, judge tokens × price. Using Claude Sonnet 4.5 public
pricing ($3 / $15 per Mtok in/out), a 106-attack scan with ~300 in / ~200 out
tokens per attack is roughly:

    106 × (300 × $3 + 200 × $15) / 1e6 ≈ **$0.41 per full scan** (target only)

Doubling for the judge gives ≈ $0.8. The offline runs cost $0 (no LLM); this is
recorded as `cost_usd_total = 0` and labelled accordingly.

## Reproducing

`make eval` regenerates the synthetic numbers; `make eval-p01` / `make eval-p03`
regenerate the real-target numbers (targets must be running locally).
