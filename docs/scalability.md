# Scalability — AI Safety & Red Teaming Framework

How the framework holds up as the corpus, the number of targets and the request
volume grow. Honest about where it breaks.

## Current capacity

- The runner scans the 106-attack corpus against a local target in well under a
  second when the target is a deterministic stub; latency is dominated by the
  target, not the framework.
- Concurrency is bounded by an `asyncio.Semaphore` (`MAX_CONCURRENCY`, default 8)
  so a scan never stampedes the target. Against Project 01 we lowered it to 4 to
  stay under its own 60/minute rate limit.
- Memory is a few hundred MB without ML detectors.

## 10× (bigger corpus, more targets)

- The corpus is data; 1,000+ attacks (HarmBench has 400, JailbreakBench 100+)
  load and run the same way. Aggregation is O(n) per run.
- Multiple targets scan independently; run them as separate `eval.run`
  invocations or API calls.
- What needs attention: the target's own rate limits become the bottleneck.
  Tune `MAX_CONCURRENCY` and lean on the tenacity backoff.

## 100× (continuous scanning, ML detectors on)

- ML detectors on CPU are the cost centre. Batch inputs through the pipeline and
  cache detections by text hash; pin the models and warm them once at startup.
- Move persistence to Postgres (`DATABASE_URL`) with the connection pool.
- Split scanning from reporting: the runner writes runs; a scheduled job renders
  PDFs and regenerates `RESULTS.md`.

## 1000× (fleet of targets, scheduled regression)

- Shard by target and run scans as queued jobs (Celery/RQ + Redis or SQS).
- GPU for the ML detectors if toxicity/injection classification dominates.
- Store per-run documents in object storage; keep only summaries in the hot DB.

## What we would not scale

The eval corpus is intentionally stable so success rates are comparable across
runs. Growth means *more kinds* of attacks (new OWASP techniques, encodings,
multi-turn), not re-running the same corpus at higher parallelism.
