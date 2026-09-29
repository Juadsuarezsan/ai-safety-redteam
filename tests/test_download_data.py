"""Tests for the data download script (network mocked with respx)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from scripts import download_data

_HARMBENCH_CSV = (
    "Behavior,FunctionalCategory,SemanticCategory,Tags,ContextString,BehaviorID\n"
    "Do a bad thing,standard,illegal,,,bad_thing_1\n"
    "Do another bad thing,standard,cybercrime_intrusion,,,bad_thing_2\n"
)
_JBB_JSON = json.dumps(
    {
        "parameters": {"method": "PAIR"},
        "jailbreaks": [
            {
                "index": 0,
                "goal": "do X",
                "behavior": "B",
                "category": "Malware/Hacking",
                "prompt": "p",
            },
            {"index": 1, "goal": "do Y", "behavior": "B", "category": "Fraud", "prompt": "p2"},
        ],
    }
)


@respx.mock
def test_download_writes_manifest_and_sample(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(download_data, "DATA_DIR", tmp_path)
    monkeypatch.setattr(download_data, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(download_data, "LICENSE_DIR", tmp_path / "licenses")
    monkeypatch.setattr(download_data, "MANIFEST", tmp_path / "MANIFEST.txt")
    monkeypatch.setattr(download_data, "SAMPLE", tmp_path / "sample.json")

    respx.get(download_data.HARMBENCH_CSV).mock(
        return_value=httpx.Response(200, text=_HARMBENCH_CSV)
    )
    respx.get(download_data.HARMBENCH_LICENSE).mock(return_value=httpx.Response(200, text="MIT"))
    respx.get(download_data.JBB_ARTIFACT).mock(return_value=httpx.Response(200, text=_JBB_JSON))
    respx.get(download_data.JBB_LICENSE).mock(return_value=httpx.Response(200, text="MIT"))

    download_data.run(sample_size=4)

    manifest = (tmp_path / "MANIFEST.txt").read_text()
    assert "sha256:" in manifest
    assert "harmbench_behaviors_text_all.csv" in manifest

    sample = json.loads((tmp_path / "sample.json").read_text())
    assert len(sample) >= 2
    sources = {r["source"] for r in sample}
    assert sources == {"harmbench", "jailbreakbench"}
    for record in sample:
        assert record["ground_truth"] == "refuse"
        assert record["owasp"].startswith("LLM")


def test_count_records_csv() -> None:
    n = download_data._count_records("x.csv", _HARMBENCH_CSV.encode())
    assert n == 2


def test_count_records_jbb_json() -> None:
    n = download_data._count_records("x.json", _JBB_JSON.encode())
    assert n == 2
