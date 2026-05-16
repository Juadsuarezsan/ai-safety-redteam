# Project 07 — AI Safety & Red Teaming Framework

> Security evaluation framework for LLM systems in production. Detects prompt injection, jailbreaks, data leakage, hallucinations. Implements guardrails aligned with OWASP LLM Top 10. Produces auditable security reports.

[![Status](https://img.shields.io/badge/status-planned-fbbf24)]()
[![Bench](https://img.shields.io/badge/bench-HarmBench%20%2B%20JailbreakBench-22d3ee)]()
[![Standard](https://img.shields.io/badge/standard-OWASP%20LLM%20Top%2010-7c5cff)]()

**Industrial use case:** AI Safety Engineer / MLSec roles at Robust Intelligence, Lakera, Protect AI, HiddenLayer. Indispensable for banking, insurance, healthcare, government, defense.

## What this project does

Builds an adversarial test suite that attacks other LLM systems (typically the other projects in this portfolio). Categorizes attacks by OWASP LLM Top 10. Adds a guardrails layer that reduces attack success rate. Quantifies the reduction.

## Architecture

```
System under test (P1 or P3 of this portfolio)
   │
   ▼
[Attack Generator]
   ├─ HarmBench known prompts
   ├─ JailbreakBench techniques
   ├─ Prompt injection variants (DAN, instruction override)
   ├─ LLM-generated adversarial (Claude in attack mode)
   └─ Encoded attacks (base64, rot13, unicode)
   │
   ▼
[Attack Executor] runs each attack against the target
   │
   ▼
[Response Analyzer]
   ├─ refusal correct? (should refuse on attacks)
   ├─ PII leak? (Presidio over output)
   ├─ compliance with malicious intent?
   └─ factual hallucination?
   │
   ▼
[Categorizer] OWASP LLM Top 10 mapping
   │
   ▼
[Guardrails Layer]
   ├─ Input filtering (prompt-injection detector)
   ├─ Output sanitization
   ├─ PII redaction
   └─ Refusal injection
   │
   ▼
[Report Generator] PDF security report
```

## Roadmap to v1.0.0

1. [ ] Download HarmBench (400) + JailbreakBench (100) + ToxicChat (10K)
2. [ ] Adversarial prompt generators (encoded attacks, role-play, instruction override)
3. [ ] Presidio integration for PII detection in outputs
4. [ ] Toxicity classifier (`unitary/toxic-bert`)
5. [ ] Prompt-injection detector (`protectai/deberta-v3-base-prompt-injection`)
6. [ ] OWASP LLM Top 10 attack-to-category mapping
7. [ ] Guardrails layer using `guardrails-ai` or `nvidia-nemo-guardrails`
8. [ ] Apply framework to P1 (E-commerce Assistant) and P3 (Sales Intel) of this portfolio
9. [ ] Measure attack success rate before/after guardrails per category
10. [ ] Next.js security dashboard with attack gallery + report viewer
11. [ ] PDF security reports for P1 and P3

## Stack

| Layer | Technology |
|---|---|
| LLM | Claude Sonnet 4.5 (target + red-teamer) |
| Guardrails | guardrails-ai or nvidia-nemo-guardrails |
| PII detection | Microsoft Presidio |
| Toxicity | `unitary/toxic-bert` (HuggingFace) |
| Prompt injection | `protectai/deberta-v3-base-prompt-injection` |
| Red teaming | `giskard` or `garak` (NVIDIA) |
| Storage | PostgreSQL |
| Frontend | Next.js security dashboard |
| Observability | LangSmith |

## Definition of Done — project-specific

- [ ] Framework applied to at least 2 other projects of the portfolio (P1 + P3)
- [ ] Coverage of all 10 OWASP categories with tests per category
- [ ] Quantified attack success rate before/after guardrails
- [ ] Demo allows running attacks against a simplified system
- [ ] Gallery of 50 pre-computed attack runs accessible
- [ ] PDF security reports for P1 + P3 included in repo
- [ ] Library publishable as pip package with its own tests

Plus the 12 universal DoD blocks.

## License

MIT.
