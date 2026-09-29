.PHONY: install install-ml lint format typecheck test eval eval-p01 eval-p03 report data demo-bake gitleaks build clean

PY ?= .venv/bin/python
PIP ?= .venv/bin/pip

install:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

install-ml:
	$(PIP) install -e ".[dev,ml]"

lint:
	.venv/bin/ruff check .
	.venv/bin/black --check .

format:
	.venv/bin/ruff check . --fix
	.venv/bin/black .

typecheck:
	.venv/bin/mypy --strict src/

test:
	$(PY) -m pytest --cov=src --cov-report=term-missing --cov-fail-under=70

eval:
	$(PY) -m eval.run --target synthetic --name synthetic

eval-p01:
	$(PY) -m eval.run --target http --url http://localhost:8001 --adapter chat \
		--label "Project 01 — conversational e-commerce assistant (deterministic fallback, no LLM)" \
		--name p01-chat --concurrency 4

eval-p03:
	$(PY) -m eval.run --target http --url http://localhost:8003 --adapter research \
		--label "Project 03 — sales intelligence agent (deterministic stubs, no LLM)" \
		--name p03-research --concurrency 4

report:
	$(PY) -m ai_safety_framework.cli report eval/runs/2026-09-29-p01-chat.json -o eval/reports/security-report-p01-chat.pdf
	$(PY) -m ai_safety_framework.cli report eval/runs/2026-09-29-p03-research.json -o eval/reports/security-report-p03-research.pdf

data:
	$(PY) scripts/download_data.py

demo-bake:
	$(PY) scripts/bake_demo.py

gitleaks:
	gitleaks detect --no-banner --redact

build:
	$(PY) -m build

clean:
	rm -rf build dist src/*.egg-info .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
