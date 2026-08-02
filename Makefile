.DEFAULT_GOAL := help
PY := python

.PHONY: help install lint format typecheck test cov check example checks permissions build clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Editable install with dev extras
	$(PY) -m pip install -e ".[dev]"

lint: ## Ruff lint and format check
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format: ## Apply Ruff autofixes and formatting
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

typecheck: ## mypy in strict mode
	$(PY) -m mypy

test: ## Run the test suite
	$(PY) -m pytest

cov: ## Run tests with a coverage report
	$(PY) -m pytest --cov --cov-report=term-missing

check: lint typecheck cov ## Everything CI runs

example: ## Scan a simulated account offline and print findings
	$(PY) examples/scan_local.py

checks: ## List the check catalogue
	basalt-aws checks -v

permissions: ## Show the IAM permissions a scan requires
	basalt-aws permissions

build: ## Build the sdist and wheel
	$(PY) -m build

clean: ## Remove build and cache artefacts
	rm -rf build dist *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
