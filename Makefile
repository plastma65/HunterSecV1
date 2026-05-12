.PHONY: help setup install lint fmt test test-unit test-int test-e2e cov docs sandbox secrets-scan sbom clean

SHELL := /bin/bash
PYTHON ?= python3.11
UV ?= uv

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Install dev deps + pre-commit hooks
	$(UV) venv --python $(PYTHON)
	$(UV) pip install -e ".[dev,web,docs]"
	$(UV) run pre-commit install
	@echo "Setup complete. Activate venv: source .venv/bin/activate"

install: ## Install runtime deps only
	$(UV) pip install -e .

lint: ## Run all linters
	$(UV) run ruff check src tests
	$(UV) run ruff format --check src tests
	$(UV) run mypy src
	$(UV) run bandit -c pyproject.toml -r src
	$(UV) run detect-secrets scan --baseline .secrets.baseline

fmt: ## Auto-format
	$(UV) run ruff check --fix src tests
	$(UV) run ruff format src tests
	$(UV) run black src tests

test: test-unit ## Alias for test-unit

test-unit: ## Run unit tests
	$(UV) run pytest tests/unit -m "not integration and not e2e"

test-int: ## Run integration tests (needs Docker)
	$(UV) run pytest tests/integration -m "integration"

test-e2e: ## Run E2E tests (lab required)
	$(UV) run pytest tests/e2e -m "e2e"

test-all: ## Run all test categories
	$(UV) run pytest

cov: ## Generate coverage HTML report
	$(UV) run pytest --cov=src/huntersec --cov-report=html
	@echo "Open htmlcov/index.html"

docs: ## Build & serve docs
	$(UV) run mkdocs serve

docs-build: ## Build docs to site/
	$(UV) run mkdocs build --strict

sandbox: ## Build Kali Docker image
	docker build -t huntersec/kali:latest -f docker/Dockerfile.kali docker/
	@echo "Built huntersec/kali:latest"

sandbox-test: sandbox ## Verify sandbox image
	docker run --rm huntersec/kali:latest nmap --version

secrets-scan: ## Scan for leaked secrets
	$(UV) run detect-secrets scan --baseline .secrets.baseline
	$(UV) run gitleaks detect --no-git -v

sbom: ## Generate SBOM (requires syft)
	@command -v syft >/dev/null 2>&1 || { echo "Install syft: brew install syft / apt install syft"; exit 1; }
	syft packages dir:. -o spdx-json=dist/sbom.spdx.json
	@echo "SBOM written to dist/sbom.spdx.json"

clean: ## Remove build artifacts and caches
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache .hypothesis
	rm -rf htmlcov coverage.xml .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

bench: ## Run benchmark suite
	$(UV) run python -m benchmarks.runner

ci-local: lint test cov ## Simulate CI locally
	@echo "All CI checks passed locally."
