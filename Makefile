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

signing-check: ## Check signing identity (prompts for missing KEY_SLOT/SIGNING_KEY)
	@slot='$(KEY_SLOT)'; key='$(SIGNING_KEY)'; \
	if test -z "$$slot"; then printf 'Key slot (a, b, or c): ' >/dev/tty 2>/dev/null && IFS= read -r slot </dev/tty || { echo 'KEY_SLOT is required (non-interactive example: make signing-check KEY_SLOT=a SIGNING_KEY=FULL_FINGERPRINT)' >&2; exit 2; }; fi; \
	if test -z "$$key"; then printf 'Full primary key fingerprint for slot %s: ' "$$slot" >/dev/tty 2>/dev/null && IFS= read -r key </dev/tty || { echo 'SIGNING_KEY is required (use the full primary fingerprint)' >&2; exit 2; }; fi; \
	$(PYTHON) scripts/check-signing-key.py "$(ROOT)" "$$slot" "$$key" || exit $$?; \
	printf '\nNext steps:\n  1. Compare the artifact hashes with the coordinator.\n  2. Run make sign-all KEY_SLOT=%s SIGNING_KEY=%s\n' "$$slot" "$$key"

release-check: root-check ## Check clean source and release inputs
	@test -z "$$(git status --porcelain)" || { echo "Git worktree or index has uncommitted changes" >&2; exit 2; }
	@test -n "$(PACKAGE_VERSION)" || { echo "PACKAGE_VERSION could not be read" >&2; exit 2; }
	@echo "Release inputs valid: version $(PACKAGE_VERSION), commit $$(git rev-parse HEAD)"

release-manifest: root-check ## Generate release manifest (prompts for MANIFEST_VERSION)
	@version='$(MANIFEST_VERSION)'; \
	if test -z "$$version"; then printf 'Release manifest version (positive integer): ' >/dev/tty 2>/dev/null && IFS= read -r version </dev/tty || { echo 'MANIFEST_VERSION is required (non-interactive example: make release-manifest MANIFEST_VERSION=1)' >&2; exit 2; }; fi; \
	case "$$version" in ''|*[!0-9]*) echo 'MANIFEST_VERSION must be a positive integer' >&2; exit 2;; esac; \
	test "$$version" -gt 0 || { echo 'MANIFEST_VERSION must be a positive integer' >&2; exit 2; }; \
	test "$(FORCE)" = 1 || test ! -e release-manifest.json || { echo "release-manifest.json exists; use FORCE=1 only after deciding to replace it" >&2; exit 2; }; \
	$(INTEGRITY) generate-manifest --root-dir . --output release-manifest.json --project caretaker --package-version "$(PACKAGE_VERSION)" --manifest-type release --manifest-version "$$version" --root-version "$(ROOT_VERSION)" --root-policy "$(ROOT)" --include 'src/caretaker/**/*.py' || exit $$?; \
	printf '\nNext steps:\n  1. Run make inspect-integrity and review release-manifest.json.\n  2. Transfer the reviewed manifest to each signing station.\n  3. On each station run make sign-release (it will prompt if needed).\n'

protected-manifest: root-check ## Generate protected manifest (prompts for MANIFEST_VERSION)
	@version='$(MANIFEST_VERSION)'; \
	if test -z "$$version"; then printf 'Protected manifest version (positive integer): ' >/dev/tty 2>/dev/null && IFS= read -r version </dev/tty || { echo 'MANIFEST_VERSION is required (non-interactive example: make protected-manifest MANIFEST_VERSION=1)' >&2; exit 2; }; fi; \
	case "$$version" in ''|*[!0-9]*) echo 'MANIFEST_VERSION must be a positive integer' >&2; exit 2;; esac; \
	test "$$version" -gt 0 || { echo 'MANIFEST_VERSION must be a positive integer' >&2; exit 2; }; \
	test "$(FORCE)" = 1 || test ! -e protected-manifest.json || { echo "protected-manifest.json exists; use FORCE=1 only after deciding to replace it" >&2; exit 2; }; \
	$(INTEGRITY) generate-manifest --root-dir . --output protected-manifest.json --project caretaker --package-version "$(PACKAGE_VERSION)" --manifest-type protected --manifest-version "$$version" --root-version "$(ROOT_VERSION)" --root-policy "$(ROOT)" || exit $$?; \
	printf '\nNext steps:\n  1. Run make inspect-integrity and review protected-manifest.json.\n  2. Transfer the reviewed manifest to each signing station.\n  3. On each station run make sign-protected (it will prompt if needed).\n'

manifests: root-check ## Generate both manifests (prompts for missing versions)
	@release='$(RELEASE_MANIFEST_VERSION)'; protected='$(PROTECTED_MANIFEST_VERSION)'; \
	if test -z "$$release"; then printf 'Release manifest version (positive integer): ' >/dev/tty 2>/dev/null && IFS= read -r release </dev/tty || { echo 'RELEASE_MANIFEST_VERSION is required' >&2; exit 2; }; fi; \
	if test -z "$$protected"; then printf 'Protected manifest version (positive integer): ' >/dev/tty 2>/dev/null && IFS= read -r protected </dev/tty || { echo 'PROTECTED_MANIFEST_VERSION is required' >&2; exit 2; }; fi; \
	case "$$release:$$protected" in *[!0-9:]*) echo 'Manifest versions must be positive integers' >&2; exit 2;; esac; \
	test "$$release" -gt 0 && test "$$protected" -gt 0 || { echo 'Manifest versions must be positive integers' >&2; exit 2; }; \
	$(MAKE) --no-print-directory release-manifest MANIFEST_VERSION="$$release" PACKAGE_VERSION="$(PACKAGE_VERSION)" ROOT="$(ROOT)" || exit $$?; \
	$(MAKE) --no-print-directory protected-manifest MANIFEST_VERSION="$$protected" PACKAGE_VERSION="$(PACKAGE_VERSION)" ROOT="$(ROOT)" || exit $$?; \
	printf '\nNext steps:\n  1. Review both manifests and record their SHA-256 values.\n  2. Copy root.json and both manifests to each signing station.\n  3. Run make sign-all independently on stations A, B, and C.\n'

inspect-integrity: ## Display root and available manifest metadata and hashes
	$(INTEGRITY) inspect "$(ROOT)"
	@test ! -f release-manifest.json || $(INTEGRITY) inspect release-manifest.json
	@test ! -f protected-manifest.json || $(INTEGRITY) inspect protected-manifest.json

sign: ## Sign one manifest (prompts for missing SIGNING_KEY)
	@test -f "$(MANIFEST)" || { echo "Manifest not found: $(MANIFEST)" >&2; echo "Generate and review a canonical release manifest before signing." >&2; exit 2; }
	@key='$(SIGNING_KEY)'; \
	if test -z "$$key"; then printf 'Full primary signing-key fingerprint: ' >/dev/tty 2>/dev/null && IFS= read -r key </dev/tty || { echo 'SIGNING_KEY is required (non-interactive example: make sign SIGNING_KEY=FULL_FINGERPRINT)' >&2; exit 2; }; fi; \
	./scripts/sign-code.sh "$(MANIFEST)" "$$key" "$(SIGNATURE)"

sign-root: ## Sign root.json (prompts for missing slot/key)
	@$(MAKE) --no-print-directory _sign-artifacts SIGN_ARTIFACTS='$(ROOT)'

sign-release: ## Sign release manifest (prompts for missing slot/key)
	@$(MAKE) --no-print-directory _sign-artifacts SIGN_ARTIFACTS='release-manifest.json'

sign-protected: ## Sign protected manifest (prompts for missing slot/key)
	@$(MAKE) --no-print-directory _sign-artifacts SIGN_ARTIFACTS='protected-manifest.json'

sign-all: ## Sign root and both manifests (prompts once for missing slot/key)
	@$(MAKE) --no-print-directory _sign-artifacts SIGN_ARTIFACTS='$(ROOT) release-manifest.json protected-manifest.json'

.PHONY: _sign-artifacts
_sign-artifacts:
	@slot='$(KEY_SLOT)'; key='$(SIGNING_KEY)'; \
	if test -z "$$slot"; then printf 'Key slot (a, b, or c): ' >/dev/tty 2>/dev/null && IFS= read -r slot </dev/tty || { echo 'KEY_SLOT is required (non-interactive example: make sign-all KEY_SLOT=a SIGNING_KEY=FULL_FINGERPRINT)' >&2; exit 2; }; fi; \
	if test -z "$$key"; then printf 'Full primary key fingerprint for slot %s: ' "$$slot" >/dev/tty 2>/dev/null && IFS= read -r key </dev/tty || { echo 'SIGNING_KEY is required (use the full primary fingerprint)' >&2; exit 2; }; fi; \
	$(PYTHON) scripts/check-signing-key.py "$(ROOT)" "$$slot" "$$key" || exit $$?; \
	slot=$$(printf '%s' "$$slot" | tr 'A-Z' 'a-z'); \
	for artifact in $(SIGN_ARTIFACTS); do \
		test -f "$$artifact" || { echo "Artifact not found: $$artifact" >&2; exit 2; }; \
		./scripts/sign-code.sh "$$artifact" "$$key" "$$artifact.key-$$slot.asc" || exit $$?; \
	done; \
	printf '\nNext steps:\n  1. Export only the .asc signature file(s); do not export private key material.\n  2. Return the signature(s) to the coordinator with the reviewed SHA-256 values.\n  3. Repeat on the other independent signing stations.\n  4. After collecting A, B, and C, run make verify-all PUBLICATION_DIR=.\n'

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
