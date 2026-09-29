# Technical decisions — AI Safety & Red Teaming Framework

## 1. Detectors behind a `Protocol` with lazy ML imports

The regex detectors are always on and dependency-free, so CI and a fresh clone
work with a ~200 MB install. The ML detectors (DeBERTa prompt-injection,
`unitary/toxic-bert`, Presidio) implement the same `Detector` Protocol but are
imported *inside* their constructors and live in the optional `ml` extra
(≈6 GB with CUDA wheels). Rejected: making torch a base dependency — it breaks
CI, bloats the image and is unnecessary for the regex baseline. The loader is
injectable, so ML detectors are unit-tested with fakes without any download.

## 2. Attack success is rule-based first, LLM-judge second

Each attack carries hand-written `success_indicators`; success = the target did
not refuse AND complied (indicator present, PII leaked, or an oversized response
for DoS probes). This is deterministic, free and reproducible in CI. The
LLM-as-judge with a numbered 1–5 rubric is layered on top for nuance and is gated
on `ANTHROPIC_API_KEY`. Rejected: judge-only scoring — non-reproducible and
spends credits on every run.

## 3. `HttpTarget` with adapters, not one hard-coded client

Systems under test differ in payload and response shape, so the target is one
class plus a small `(path, build_request, extract_reply)` adapter per system.
Adding Project 03 was ~10 lines. httpx gives async + explicit timeouts; tenacity
retries only 5xx/network (never 4xx — a 422 is a deterministic rejection, i.e. a
defense, surfaced as a refusal). Rejected: retrying 4xx (pointless) and a
requests-based sync client (blocks the event loop).

## 4. Model pinned to a dated ID

`claude-sonnet-4-5-20250929`, never `claude-latest`, so red-teamer and judge runs
are comparable over time. Timeouts and tenacity wrap every external call.

## 5. Deterministic fallback labelled everywhere

Both synthetic targets and every run record their `mode`. A run without an LLM is
labelled *deterministic fallback, no LLM* in `RESULTS.md`, the README and the PDF,
and is never shown as the target's real quality. This keeps the anti-fabrication
rule enforceable: numbers come only from a saved `eval/runs/*.json`.

## 6. SQLite by default, Postgres behind the same interface

The run store is a Protocol with a SQLite implementation (zero-ops, works in CI
and on a fresh clone) and a psycopg-pool Postgres implementation for production.
`get_repository` picks Postgres when `DATABASE_URL` is set and falls back to
SQLite if the database is unreachable. Rejected: requiring Postgres to run the
tool at all.

## 7. Installable package (`ai_safety_framework`), eval harness kept out of it

Domain code lives in `src/ai_safety_framework/` and ships as a wheel with a
console script; the `eval/` harness stays at the repo root and is not packaged,
because it is a development/reporting tool, not library API.
