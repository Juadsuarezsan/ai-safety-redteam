"""Side-by-side eval: VulnerableTarget vs GuardrailedTarget."""
from __future__ import annotations

import argparse
import asyncio
import json

from src.agent.runner import run_red_team
from src.attacks.library import all_attacks
from src.targets.test_target import GuardrailedTarget, VulnerableTarget


async def run_eval() -> dict:
    attacks = all_attacks()
    raw = await run_red_team(attacks, VulnerableTarget())
    guarded = await run_red_team(attacks, GuardrailedTarget())
    return {
        "n_attacks": len(attacks),
        "vulnerable_target": {
            "success_rate": raw.success_rate,
            "by_category": raw.by_category,
        },
        "guarded_target": {
            "success_rate": guarded.success_rate,
            "by_category": guarded.by_category,
        },
        "reduction": raw.success_rate - guarded.success_rate,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    r = asyncio.run(run_eval())
    if args.json:
        print(json.dumps(r, indent=2, default=str))
    else:
        print(f"Attacks: {r['n_attacks']}")
        print(f"Vulnerable success rate: {r['vulnerable_target']['success_rate']:.1%}")
        print(f"Guarded success rate:    {r['guarded_target']['success_rate']:.1%}")
        print(f"Reduction:               {r['reduction']:.1%}")


if __name__ == "__main__":
    main()
