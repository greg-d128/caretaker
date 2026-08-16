PYTHON ?= python3
VENV   ?= venv
BIN     := $(VENV)/bin

# Release-signing defaults. MANIFEST.in is packaging metadata, not a release
# integrity manifest; generate and review this JSON file before signing it.
MANIFEST  ?= release-manifest.json
SIGNATURE ?= $(MANIFEST).asc
ROOT ?= root.json
PUBLICATION_DIR ?= .
PUBLIC_KEYS ?=
PACKAGE_VERSION ?= $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml | head -n 1)
ROOT_VERSION ?= $(shell $(PYTHON) -c 'import json; print(json.load(open("$(ROOT)"))["root_version"])' 2>/dev/null)
INTEGRITY := PYTHONPATH=src $(PYTHON) -m caretaker.integrity.cli

.DEFAULT_GOAL := help

.PHONY: help setup test compile check wheel build verify-wheel root-check signing-check release-check release-manifest protected-manifest manifests inspect-integrity sign sign-root sign-release sign-protected sign-all verify-signature verify-all lab lab-console profile clean distclean

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <command>\n\nCommands:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Create the development virtual environment
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip build pytest cryptography 'textual>=0.80'

test: ## Run tests against the source tree
	PYTHONPATH=src $(BIN)/python -m pytest -q

compile: ## Compile the source, tests, and examples
	$(BIN)/python -m compileall -q src tests examples scripts

check: test compile ## Run source tests and compilation checks

wheel: ## Build the wheel in dist/
	$(BIN)/python -m build --wheel

build: ## Build the wheel and source distribution in dist/
	$(BIN)/python -m build

root-check: ## Validate root policy and optional PUBLIC_KEYS
	$(INTEGRITY) inspect "$(ROOT)"
	$(PYTHON) scripts/check-root.py "$(ROOT)" . $(PUBLIC_KEYS)

signing-check: ## Check KEY_SLOT and SIGNING_KEY on this signing station
	@test -n "$(KEY_SLOT)" || { echo "KEY_SLOT is required (a, b, or c)" >&2; exit 2; }
	@test -n "$(SIGNING_KEY)" || { echo "SIGNING_KEY is required" >&2; exit 2; }
	$(PYTHON) scripts/check-signing-key.py "$(ROOT)" "$(KEY_SLOT)" "$(SIGNING_KEY)"

release-check: root-check ## Check clean source and release inputs
	@test -z "$$(git status --porcelain)" || { echo "Git worktree or index has uncommitted changes" >&2; exit 2; }
	@test -n "$(PACKAGE_VERSION)" || { echo "PACKAGE_VERSION could not be read" >&2; exit 2; }
	@echo "Release inputs valid: version $(PACKAGE_VERSION), commit $$(git rev-parse HEAD)"

release-manifest: root-check ## Generate release manifest; requires MANIFEST_VERSION
	@test -n "$(MANIFEST_VERSION)" || { echo "MANIFEST_VERSION is required" >&2; exit 2; }
	@test "$(FORCE)" = 1 || test ! -e release-manifest.json || { echo "release-manifest.json exists; use FORCE=1 only after deciding to replace it" >&2; exit 2; }
	$(INTEGRITY) generate-manifest --root-dir . --output release-manifest.json --project caretaker --package-version "$(PACKAGE_VERSION)" --manifest-type release --manifest-version "$(MANIFEST_VERSION)" --root-version "$(ROOT_VERSION)" --root-policy "$(ROOT)" --include 'src/caretaker/**/*.py'

protected-manifest: root-check ## Generate protected manifest; requires MANIFEST_VERSION
	@test -n "$(MANIFEST_VERSION)" || { echo "MANIFEST_VERSION is required" >&2; exit 2; }
	@test "$(FORCE)" = 1 || test ! -e protected-manifest.json || { echo "protected-manifest.json exists; use FORCE=1 only after deciding to replace it" >&2; exit 2; }
	$(INTEGRITY) generate-manifest --root-dir . --output protected-manifest.json --project caretaker --package-version "$(PACKAGE_VERSION)" --manifest-type protected --manifest-version "$(MANIFEST_VERSION)" --root-version "$(ROOT_VERSION)" --root-policy "$(ROOT)"

manifests: root-check ## Generate both manifests with explicit version variables
	@test -n "$(RELEASE_MANIFEST_VERSION)" || { echo "RELEASE_MANIFEST_VERSION is required" >&2; exit 2; }
	@test -n "$(PROTECTED_MANIFEST_VERSION)" || { echo "PROTECTED_MANIFEST_VERSION is required" >&2; exit 2; }
	$(MAKE) release-manifest MANIFEST_VERSION="$(RELEASE_MANIFEST_VERSION)" PACKAGE_VERSION="$(PACKAGE_VERSION)" ROOT="$(ROOT)"
	$(MAKE) protected-manifest MANIFEST_VERSION="$(PROTECTED_MANIFEST_VERSION)" PACKAGE_VERSION="$(PACKAGE_VERSION)" ROOT="$(ROOT)"

inspect-integrity: ## Display root and available manifest metadata and hashes
	$(INTEGRITY) inspect "$(ROOT)"
	@test ! -f release-manifest.json || $(INTEGRITY) inspect release-manifest.json
	@test ! -f protected-manifest.json || $(INTEGRITY) inspect protected-manifest.json

sign: ## Sign release-manifest.json (override with MANIFEST/SIGNATURE)
	@test -f "$(MANIFEST)" || { echo "Manifest not found: $(MANIFEST)" >&2; echo "Generate and review a canonical release manifest before signing." >&2; exit 2; }
	@test -n "$(SIGNING_KEY)" || { echo "SIGNING_KEY is required" >&2; exit 2; }
	./scripts/sign-code.sh "$(MANIFEST)" "$(SIGNING_KEY)" "$(SIGNATURE)"

sign-root: signing-check ## Sign root.json using KEY_SLOT and SIGNING_KEY
	./scripts/sign-code.sh "$(ROOT)" "$(SIGNING_KEY)" "$(ROOT).key-$$(printf '%s' "$(KEY_SLOT)" | tr 'A-Z' 'a-z').asc"

sign-release: signing-check ## Sign release manifest using KEY_SLOT and SIGNING_KEY
	./scripts/sign-code.sh release-manifest.json "$(SIGNING_KEY)" "release-manifest.json.key-$$(printf '%s' "$(KEY_SLOT)" | tr 'A-Z' 'a-z').asc"

sign-protected: signing-check ## Sign protected manifest using KEY_SLOT and SIGNING_KEY
	./scripts/sign-code.sh protected-manifest.json "$(SIGNING_KEY)" "protected-manifest.json.key-$$(printf '%s' "$(KEY_SLOT)" | tr 'A-Z' 'a-z').asc"

sign-all: signing-check ## Sign root and both manifests on one signing station
	$(MAKE) sign-root KEY_SLOT="$(KEY_SLOT)" SIGNING_KEY="$(SIGNING_KEY)" ROOT="$(ROOT)"
	$(MAKE) sign-release KEY_SLOT="$(KEY_SLOT)" SIGNING_KEY="$(SIGNING_KEY)" ROOT="$(ROOT)"
	$(MAKE) sign-protected KEY_SLOT="$(KEY_SLOT)" SIGNING_KEY="$(SIGNING_KEY)" ROOT="$(ROOT)"

verify-signature: ## Verify detached SIGNATURE over MANIFEST with local GnuPG
	@test -f "$(MANIFEST)" || { echo "Manifest not found: $(MANIFEST)" >&2; exit 2; }
	@test -f "$(SIGNATURE)" || { echo "Signature not found: $(SIGNATURE)" >&2; exit 2; }
	gpg --verify "$(SIGNATURE)" "$(MANIFEST)"

verify-all: ## Verify conventional root, release, and protected publication files
	PYTHONPATH=src $(PYTHON) scripts/verify-publication.py "$(PUBLICATION_DIR)"

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
