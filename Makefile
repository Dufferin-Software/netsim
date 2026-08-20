.PHONY: lint format type-check dead-code test test-suite clean help

help:
	@echo "Available commands:"
	@echo "  make lint        - Run ruff linter"
	@echo "  make format      - Format code with ruff"
	@echo "  make type-check  - Run mypy type checker"
	@echo "  make dead-code   - Find unused functions/methods/classes (vulture)"
	@echo "  make lint-all    - Run all linting (ruff + mypy + dead-code)"
	@echo "  make test        - Run every suite (one pytest run each)"
	@echo "  make test-suite SUITE=two_node_iperf - Run one suite"
	@echo "  make clean       - Remove build artifacts"

lint:
	poetry run ruff check netsim/ tests/

format:
	poetry run ruff format netsim/ tests/
	poetry run ruff check --unsafe-fixes --fix netsim/ tests/

type-check:
	poetry run mypy .

# Detect dead code (unused functions/methods/classes) in the netsim/ package.
# Paths and the false-positive whitelist live in [tool.vulture] in pyproject.toml.
# False positives belong in vulture_whitelist.py, not suppressed here.
dead-code:
	poetry run vulture

lint-all: lint type-check dead-code

# One pytest invocation per suite. They cannot share a session: tests/ is a
# single package, so the package-scoped topology fixture is set up once and a
# second suite would run against the first suite's VMs.
test:
	tests/run_all.sh

test-suite:
	@test -n "$(SUITE)" || { echo "usage: make test-suite SUITE=<name>"; exit 1; }
	poetry run pytest tests/$(SUITE)/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/ .mypy_cache/ build/ dist/ *.egg-info
