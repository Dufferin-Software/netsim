.PHONY: lint format type-check test clean help

help:
	@echo "Available commands:"
	@echo "  make lint        - Run ruff linter"
	@echo "  make format      - Format code with ruff"
	@echo "  make type-check  - Run mypy type checker"
	@echo "  make lint-all    - Run all linting (ruff + mypy)"
	@echo "  make test        - Run tests"
	@echo "  make clean       - Remove build artifacts"

lint:
	poetry run ruff check netsim/ tests/

format:
	poetry run ruff format netsim/ tests/
	poetry run ruff check --unsafe-fixes --fix netsim/ tests/

type-check:
	poetry run mypy .

lint-all: lint type-check

test:
	python3 -m pytest tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/ .mypy_cache/ build/ dist/ *.egg-info
