# LinkedIn post

I built an AI Safety & Red Teaming framework for LLM applications — and pointed it
at two of my own portfolio projects.

The idea is simple: shipping an LLM feature without red-teaming it is shipping
untested security. So I built a tool that:

🔴 Fires 106 hand-labelled attacks (all 10 OWASP LLM Top 10 categories) plus
HarmBench + JailbreakBench at a running LLM system
🟣 Maps each outcome to its OWASP category and decides if the system complied,
refused, or leaked
🛡️ Adds a guardrails layer and quantifies the drop in attack success rate
📊 Measures the false-positive rate on legitimate traffic (guardrails that block
real users are worthless)
📄 Emits an auditable PDF security report

On a deliberately-vulnerable test target, the guardrails cut attack success from
26.4% to 5.7% with a 0% false-positive rate. Against my e-commerce and sales
agents (running their deterministic fallback, no LLM), the framework confirmed
they don't comply with injections and rejects malformed payloads at the door.

Engineering highlights: heavyweight ML detectors (DeBERTa prompt-injection,
toxic-bert, Presidio) sit behind a Protocol with lazy imports so the base install
stays light; the HTTP target is one client plus a tiny adapter per system;
everything is reproducible with `python -m eval.run`; 97% test coverage; pip-
installable.

Roles like AI Safety Engineer / MLSec at Robust Intelligence, Lakera, Protect AI
and HiddenLayer live exactly here.

Code + report: https://github.com/Juadsuarezsan/ai-safety-redteam

#AISafety #LLMSecurity #OWASP #RedTeaming #MLSec #AIEngineering
