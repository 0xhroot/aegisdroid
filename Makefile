.PHONY: help install install-dev install-all lint format typecheck test test-cov clean build release

PYTHON ?= python3
PIP ?= pip

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install AegisDroid
	$(PIP) install -e .

install-dev: ## Install with development dependencies
	$(PIP) install -e ".[dev]"

install-all: ## Install with all optional dependencies
	$(PIP) install -e ".[all]"

lint: ## Run linter (Ruff)
	ruff check aegisdroid tests

format: ## Format code (Ruff)
	ruff format aegisdroid tests
	ruff check --fix aegisdroid tests

typecheck: ## Run type checker (Mypy)
	mypy aegisdroid

test: ## Run tests
	pytest tests/ -v

test-cov: ## Run tests with coverage
	pytest tests/ --cov=aegisdroid --cov-report=term-missing --cov-report=html

test-fast: ## Run tests (fast, skip slow)
	pytest tests/ -v -m "not slow"

clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

build: clean ## Build distribution
	$(PYTHON) -m build

release: build ## Build and check distribution
	twine check dist/*

docker-build: ## Build Docker image
	docker build -t aegisdroid .

docker-run: ## Run Docker container
	docker run -it --rm aegisdroid

pre-commit: ## Run pre-commit on all files
	pre-commit run --all-files

docs-serve: ## Serve documentation locally (if mkdocs installed)
	mkdocs serve 2>/dev/null || echo "Install mkdocs: pip install mkdocs"

check: lint typecheck test ## Run all checks (lint + typecheck + test)

setup: ## Set up development environment
	$(PYTHON) -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -e ".[all]"
	.venv/bin/pre-commit install
	@echo "Development environment ready. Activate with: source .venv/bin/activate"
