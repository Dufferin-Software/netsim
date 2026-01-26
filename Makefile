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
	ruff check netsim/ test/

format:
	ruff format netsim/ test/
	ruff check --unsafe-fixes --fix netsim/ test/

type-check:
	mypy netsim/

lint-all: lint type-check

test:
	python3 -m pytest test/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/ .mypy_cache/ build/ dist/ *.egg-info
