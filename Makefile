PYTHON ?= python3
VENV   ?= venv
BIN     := $(VENV)/bin

.DEFAULT_GOAL := help

.PHONY: help setup test compile check wheel build verify-wheel sign lab lab-console profile clean distclean

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <command>\n\nCommands:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Create the development virtual environment
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip build pytest cryptography 'textual>=0.80'

test: ## Run tests against the source tree
	PYTHONPATH=src $(BIN)/python -m pytest -q

compile: ## Compile the source, tests, and examples
	$(BIN)/python -m compileall -q src tests examples

check: test compile ## Run source tests and compilation checks

wheel: ## Build the wheel in dist/
	$(BIN)/python -m build --wheel

build: ## Build the wheel and source distribution in dist/
	$(BIN)/python -m build

sign: ## Sign MANIFEST with SIGNING_KEY and write SIGNATURE
	@test -n "$(MANIFEST)" || { echo "MANIFEST is required" >&2; exit 2; }
	@test -n "$(SIGNING_KEY)" || { echo "SIGNING_KEY is required" >&2; exit 2; }
	@test -n "$(SIGNATURE)" || { echo "SIGNATURE is required" >&2; exit 2; }
	./scripts/sign-code.sh "$(MANIFEST)" "$(SIGNING_KEY)" "$(SIGNATURE)"

lab: ## Run the interactive Caretaker lab under caretaker-run
	PYTHONPATH=src:. $(BIN)/python -m caretaker.run --data-directory ./examples/.caretaker-interactive-lab/caretaker-data examples.interactive_caretaker_lab

lab-console: ## Open the Caretaker console for the interactive lab
	PYTHONPATH=src:. $(BIN)/python -m caretaker.console --data-directory ./examples/.caretaker-interactive-lab/caretaker-data

profile: ## Open the Textual Caretaker Profile Editor
	PYTHONPATH=src $(BIN)/python -m caretaker.profile_editor

verify-wheel: wheel ## Install and test the wheel in a temporary virtual environment
	@tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	wheel="$$(find dist -maxdepth 1 -type f -name '*.whl' -print -quit)"; \
	test -n "$$wheel" || { echo "No wheel found in dist/" >&2; exit 1; }; \
	wheel="$$(realpath "$$wheel")"; \
	$(PYTHON) -m venv "$$tmp/venv"; \
	"$$tmp/venv/bin/python" -m pip install --quiet --upgrade pip pytest; \
	"$$tmp/venv/bin/python" -m pip install --quiet "$$wheel" cryptography; \
	cp pyproject.toml "$$tmp/pyproject.toml"; \
	cp -a tests "$$tmp/tests"; \
	cd "$$tmp"; \
	"$$tmp/venv/bin/python" -c 'import caretaker; print("Version:", caretaker.__version__); print("Loaded from:", caretaker.__file__)'; \
	"$$tmp/venv/bin/python" -m pytest -q -m "not repository" tests

clean: ## Remove generated build and test files
	rm -rf build dist .pytest_cache
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +

distclean: clean ## Also remove the development virtual environment
	rm -rf $(VENV)
