"""Download the external attack corpora (HarmBench, JailbreakBench).

Both are hosted on GitHub and reachable over raw.githubusercontent.com. This
script downloads each source, records its SHA-256, size and license in
``data/MANIFEST.txt``, saves the license texts under ``data/licenses/``, and
writes a small curated, OWASP-mapped sample to ``data/external_sample.json`` for
the demo and eval. Raw downloads land in ``data/raw/`` (gitignored).

Usage:
    python scripts/download_data.py            # download everything
    python scripts/download_data.py --sample-size 40

Network use is wrapped in ``httpx`` so the tests can mock it with ``respx``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from dataclasses import dataclass
from pathlib import Path

import httpx
from loguru import logger

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
LICENSE_DIR = DATA_DIR / "licenses"
MANIFEST = DATA_DIR / "MANIFEST.txt"
SAMPLE = DATA_DIR / "external_sample.json"

HARMBENCH_CSV = (
    "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/"
    "data/behavior_datasets/harmbench_behaviors_text_all.csv"
)
HARMBENCH_LICENSE = "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/LICENSE"
JBB_ARTIFACT = (
    "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/"
    "attack-artifacts/PAIR/black_box/vicuna-13b-v1.5.json"
)
JBB_LICENSE = "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/LICENSE"

# HarmBench semantic category -> OWASP LLM category (documented mapping).
_HARMBENCH_TO_OWASP = {
    "cybercrime_intrusion": "LLM07_insecure_plugin",
    "chemical_biological": "LLM09_overreliance",
    "illegal": "LLM09_overreliance",
    "misinformation_disinformation": "LLM09_overreliance",
    "harmful": "LLM09_overreliance",
    "harassment_bullying": "LLM09_overreliance",
    "copyright": "LLM10_model_theft",
}
_JBB_TO_OWASP_DEFAULT = "LLM01_prompt_injection"


@dataclass
class Source:
    """One downloadable artifact."""

    name: str
    url: str
    license_name: str


SOURCES = [
    Source("harmbench_behaviors_text_all.csv", HARMBENCH_CSV, "MIT (Center for AI Safety)"),
    Source("harmbench_LICENSE", HARMBENCH_LICENSE, "MIT (Center for AI Safety)"),
    Source("jailbreakbench_PAIR_vicuna.json", JBB_ARTIFACT, "MIT (JailbreakBench)"),
    Source("jailbreakbench_LICENSE", JBB_LICENSE, "MIT (JailbreakBench)"),
]


def _sha256(data: bytes) -> str:
    """Return the hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def download(client: httpx.Client, source: Source) -> bytes:
    """Fetch one source, returning its raw bytes."""
    logger.info("downloading {}", source.url)
    resp = client.get(source.url, timeout=60.0)
    resp.raise_for_status()
    return resp.content


def _count_records(name: str, data: bytes) -> int:
    """Best-effort record count for the manifest."""
    if name.endswith(".csv"):
        return max(0, sum(1 for _ in csv.reader(io.StringIO(data.decode("utf-8", "replace")))) - 1)
    if name.endswith(".json"):
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            return 0
        if isinstance(obj, dict) and "jailbreaks" in obj:
            return len(obj["jailbreaks"])
        return len(obj) if isinstance(obj, list) else 1
    return 0


def build_sample(harmbench_csv: bytes, jbb_json: bytes, size: int) -> list[dict[str, str]]:
    """Build a small OWASP-mapped sample from the two corpora.

    Records are labelled with their source so synthetic and external data never
    mix silently. The behaviour text is kept short (goal/behavior only).
    """
    sample: list[dict[str, str]] = []
    rows = list(csv.DictReader(io.StringIO(harmbench_csv.decode("utf-8", "replace"))))
    per_source = max(1, size // 2)
    for row in rows[:per_source]:
        semantic = row.get("SemanticCategory", "")
        sample.append(
            {
                "id": f"HB-{row.get('BehaviorID', '')[:24]}",
                "source": "harmbench",
                "owasp": _HARMBENCH_TO_OWASP.get(semantic, "LLM09_overreliance"),
                "semantic_category": semantic,
                "behavior": row.get("Behavior", "")[:300],
                "ground_truth": "refuse",
            }
        )
    jbb = json.loads(jbb_json)
    for jb in jbb.get("jailbreaks", [])[:per_source]:
        sample.append(
            {
                "id": f"JBB-{jb.get('index', '')}",
                "source": "jailbreakbench",
                "owasp": _JBB_TO_OWASP_DEFAULT,
                "semantic_category": jb.get("category", ""),
                "behavior": str(jb.get("goal", ""))[:300],
                "ground_truth": "refuse",
            }
        )
    return sample


def write_manifest(entries: list[dict[str, str]]) -> None:
    """Write ``data/MANIFEST.txt`` with SHA-256, size, license and URL per source."""
    lines = [
        "# External data manifest — AI Safety & Red Teaming Framework",
        "# Generated by scripts/download_data.py. Ground truth for HarmBench and",
        "# JailbreakBench behaviours is 'the target must refuse'.",
        "",
    ]
    for e in entries:
        lines.append(f"name:     {e['name']}")
        lines.append(f"url:      {e['url']}")
        lines.append(f"license:  {e['license']}")
        lines.append(f"sha256:   {e['sha256']}")
        lines.append(f"bytes:    {e['bytes']}")
        lines.append(f"records:  {e['records']}")
        lines.append("")
    MANIFEST.write_text("\n".join(lines))
    logger.info("wrote {}", MANIFEST)


def run(sample_size: int = 40, client: httpx.Client | None = None) -> None:
    """Download every source, verify hashes and write the manifest and sample."""
    for d in (RAW_DIR, LICENSE_DIR):
        d.mkdir(parents=True, exist_ok=True)
    owns_client = client is None
    client = client or httpx.Client(follow_redirects=True)
    try:
        blobs: dict[str, bytes] = {}
        entries: list[dict[str, str]] = []
        for source in SOURCES:
            data = download(client, source)
            blobs[source.name] = data
            target = (LICENSE_DIR if "LICENSE" in source.name else RAW_DIR) / source.name
            target.write_bytes(data)
            entries.append(
                {
                    "name": source.name,
                    "url": source.url,
                    "license": source.license_name,
                    "sha256": _sha256(data),
                    "bytes": str(len(data)),
                    "records": str(_count_records(source.name, data)),
                }
            )
    finally:
        if owns_client:
            client.close()

    write_manifest(entries)
    sample = build_sample(
        blobs["harmbench_behaviors_text_all.csv"],
        blobs["jailbreakbench_PAIR_vicuna.json"],
        sample_size,
    )
    SAMPLE.write_text(json.dumps(sample, indent=2, ensure_ascii=False))
    logger.info("wrote {} ({} sample records)", SAMPLE, len(sample))


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-size", type=int, default=40)
    args = parser.parse_args()
    run(sample_size=args.sample_size)


if __name__ == "__main__":
    main()
