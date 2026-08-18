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
PUBLIC_KEY_DIR ?= release-keys
SIGNING_BUNDLE_DIR ?= signing-bundle
# Published Caretaker root identities. Override from an independently trusted
# source when bootstrapping a checkout: make lab-verified TRUSTED_FINGERPRINTS='...'
TRUSTED_FINGERPRINTS ?= 1AA1C739DE9A94B146BD324D335D05E357D334C9 0ABD39F4E11DC0E48D88D536CD9FF2A7E82753BE F4632C96E4D3C93AE0E894564A9B0D2FBA85B411
FRAMEWORK_POLICY ?= framework-policy.json
FRAMEWORK_POLICY_ROLE ?= protected
TOOLS_PYTHON := $(if $(wildcard $(BIN)/python),$(BIN)/python,$(PYTHON))
PACKAGE_VERSION ?= $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml | head -n 1)
ROOT_VERSION ?= $(shell $(TOOLS_PYTHON) -c 'import json; print(json.load(open("$(ROOT)"))["root_version"])' 2>/dev/null)
INTEGRITY := PYTHONPATH=src $(TOOLS_PYTHON) -m caretaker.integrity.cli

.DEFAULT_GOAL := help

.PHONY: help setup test compile check wheel build verify-wheel root-check signing-check signing-status signing-bundle release-check release-manifest protected-manifest manifests generate-release-manifest generate-protected-manifest generate-manifests inspect-integrity sign sign-file sign-root sign-release sign-protected sign-framework-policy sign-release-set sign-all sign-station-bundle verify-signature verify-all verify-publication lab lab-verified lab-console profile clean distclean

help: ## Show commands grouped by operator role
	@printf '%s\n' \
	  'Usage: make <command>' '' \
	  'Development:' \
	  '  setup                    Create the development environment' \
	  '  check                    Run tests and compilation checks' \
	  '  build                    Build wheel and source distribution' \
	  '  verify-wheel             Install and test the built wheel' '' \
	  'Release coordinator:' \
	  '  release-check            Check root policy, clean source, and release inputs' \
	  '  generate-manifests       Generate release and protected manifests' \
	  '  inspect-integrity        Display root/manifest metadata and hashes' \
	  '  signing-status           Show missing artifacts, keys, and signatures' \
	  '  signing-bundle           Build the minimal offline-station directory' \
	  '  verify-publication       Verify the assembled three-key publication' '' \
	  'Signing station:' \
	  '  signing-check            Verify this station owns KEY_SLOT' \
	  '  sign-release             Sign the release manifest for KEY_SLOT' \
	  '  sign-protected           Sign the protected manifest for KEY_SLOT' \
	  '  sign-framework-policy    Sign a canonical framework policy for KEY_SLOT' \
	  '  sign-release-set         Sign both manifests for KEY_SLOT' \
	  '  sign-root                Sign root.json for KEY_SLOT' \
	  '  sign-station-bundle      Sign root and both manifests for KEY_SLOT' '' \
	  'Laboratory:' \
	  '  lab                      Run the interactive Caretaker lab' \
	  '  lab-verified             Run lab after signed release verification' \
	  '  lab-console              Open its operator console' \
	  '  profile                  Open the profile editor' '' \
	  'Advanced/compatibility: sign-file, verify-signature, clean, distclean' '' \
	  'Ordinary station example: make sign-release-set KEY_SLOT=a' \
	  'Run make signing-status at any point to see the next missing step.'

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
	@keys='$(PUBLIC_KEYS)'; \
	if test -z "$$keys"; then \
	  for slot in a b c; do candidate='$(PUBLIC_KEY_DIR)'/caretaker-key-$$slot.asc; test ! -f "$$candidate" || keys="$$keys $$candidate"; done; \
	fi; \
	test -n "$$keys" || echo 'Public certificate checks skipped: set PUBLIC_KEY_DIR or PUBLIC_KEYS.'; \
	$(TOOLS_PYTHON) scripts/check-root.py "$(ROOT)" . $$keys

signing-check: ## Check signing identity (prompts only for missing KEY_SLOT)
	@slot='$(KEY_SLOT)'; key='$(SIGNING_KEY)'; \
	if test -z "$$slot"; then printf 'Key slot (a, b, or c): ' >/dev/tty 2>/dev/null && IFS= read -r slot </dev/tty || { echo 'KEY_SLOT is required (non-interactive example: make signing-check KEY_SLOT=a)' >&2; exit 2; }; fi; \
	expected=$$($(TOOLS_PYTHON) -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_slots"].get(sys.argv[2].upper(), ""))' "$(ROOT)" "$$slot") || exit $$?; \
	test -n "$$expected" || { echo "Unknown KEY_SLOT: $$slot" >&2; exit 2; }; \
	test -n "$$key" || key="$$expected"; \
	$(TOOLS_PYTHON) scripts/check-signing-key.py "$(ROOT)" "$$slot" "$$key" || exit $$?; \
	printf '\nResolved slot %s to primary fingerprint %s.\nNext steps:\n  1. Compare the artifact hashes with the coordinator.\n  2. Run make sign-release-set KEY_SLOT=%s\n' "$$slot" "$$expected" "$$slot"

signing-status: ## Show publication artifacts, signatures, and the next missing step
	$(TOOLS_PYTHON) scripts/signing-status.py "$(PUBLICATION_DIR)" "$(ROOT)" "$(PUBLIC_KEY_DIR)"

signing-bundle: root-check ## Build a minimal offline signing-station directory
	$(TOOLS_PYTHON) scripts/create-signing-bundle.py \
	  --output "$(SIGNING_BUNDLE_DIR)" \
	  --root "$(ROOT)" \
	  --release-manifest release-manifest.json \
	  --protected-manifest protected-manifest.json \
	  --public-key-dir "$(PUBLIC_KEY_DIR)"

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
	printf '\nNext steps:\n  1. Run make inspect-integrity and review both manifests.\n  2. Run make signing-bundle PUBLIC_KEY_DIR=<certificate-directory>.\n  3. Transfer the bundle and run make sign-release-set KEY_SLOT=<station-slot>.\n'

inspect-integrity: ## Display root and available manifest metadata and hashes
	$(INTEGRITY) inspect "$(ROOT)"
	@test ! -f release-manifest.json || $(INTEGRITY) inspect release-manifest.json
	@test ! -f protected-manifest.json || $(INTEGRITY) inspect protected-manifest.json

sign-file: ## Advanced: sign one explicitly selected file/fingerprint
	@test -f "$(MANIFEST)" || { echo "Manifest not found: $(MANIFEST)" >&2; echo "Generate and review a canonical release manifest before signing." >&2; exit 2; }
	@key='$(SIGNING_KEY)'; \
	if test -z "$$key"; then printf 'Full primary signing-key fingerprint: ' >/dev/tty 2>/dev/null && IFS= read -r key </dev/tty || { echo 'SIGNING_KEY is required (advanced example: make sign-file SIGNING_KEY=FULL_FINGERPRINT)' >&2; exit 2; }; fi; \
	./scripts/sign-code.sh "$(MANIFEST)" "$$key" "$(SIGNATURE)"

sign: sign-file ## Compatibility alias for sign-file

sign-root: ## Sign root.json (prompts for missing slot)
	@$(MAKE) --no-print-directory _sign-artifacts SIGN_ARTIFACTS='$(ROOT)'

sign-release: ## Sign release manifest (prompts for missing slot)
	@$(MAKE) --no-print-directory _sign-artifacts SIGN_ARTIFACTS='release-manifest.json'

sign-protected: ## Sign protected manifest (prompts for missing slot)
	@$(MAKE) --no-print-directory _sign-artifacts SIGN_ARTIFACTS='protected-manifest.json'

sign-framework-policy: ## Sign canonical framework policy under FRAMEWORK_POLICY_ROLE
	@PYTHONPATH=src $(TOOLS_PYTHON) scripts/check-framework-policy.py "$(FRAMEWORK_POLICY)" "$(ROOT)" "$(FRAMEWORK_POLICY_ROLE)"
	@slot='$(KEY_SLOT)'; key='$(SIGNING_KEY)'; \
	if test -z "$$slot"; then printf 'Key slot (a, b, or c): ' >/dev/tty 2>/dev/null && IFS= read -r slot </dev/tty || { echo 'KEY_SLOT is required (example: make sign-framework-policy KEY_SLOT=a)' >&2; exit 2; }; fi; \
	expected=$$($(TOOLS_PYTHON) -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_slots"].get(sys.argv[2].upper(), ""))' "$(ROOT)" "$$slot") || exit $$?; \
	test -n "$$expected" || { echo "Unknown KEY_SLOT: $$slot" >&2; exit 2; }; \
	$(TOOLS_PYTHON) -c 'import json,sys; root=json.load(open(sys.argv[1])); role=root["roles"].get(sys.argv[2]); raise SystemExit(0 if role and sys.argv[3].upper() in {item.upper() for item in role["authorized_primary_fingerprints"]} else 2)' "$(ROOT)" "$(FRAMEWORK_POLICY_ROLE)" "$$expected" || { echo "Slot $$slot is not authorized for role $(FRAMEWORK_POLICY_ROLE)" >&2; exit 2; }; \
	test -n "$$key" || key="$$expected"; \
	$(TOOLS_PYTHON) scripts/check-signing-key.py "$(ROOT)" "$$slot" "$$key" || exit $$?; \
	slot=$$(printf '%s' "$$slot" | tr 'A-Z' 'a-z'); \
	./scripts/sign-code.sh "$(FRAMEWORK_POLICY)" "$$key" "$(FRAMEWORK_POLICY).key-$$slot.asc"; \
	printf '\nCreated one framework-policy signature for slot %s.\nNext steps:\n  1. Return only the .asc file to the coordinator.\n  2. Repeat independently for the remaining slots.\n  3. Configure the authority stack with role = "%s" and all collected signatures.\n' "$$slot" "$(FRAMEWORK_POLICY_ROLE)"

sign-all: ## Compatibility: sign root and both manifests for one slot
	@$(MAKE) --no-print-directory _sign-artifacts SIGN_ARTIFACTS='$(ROOT) release-manifest.json protected-manifest.json'

sign-release-set: ## Sign both release manifests for KEY_SLOT
	@$(MAKE) --no-print-directory _sign-artifacts SIGN_ARTIFACTS='release-manifest.json protected-manifest.json'

sign-station-bundle: sign-all ## Sign root and both manifests for one station

generate-release-manifest: release-manifest ## Generate the ordinary release manifest

generate-protected-manifest: protected-manifest ## Generate the protected-code manifest

generate-manifests: manifests ## Generate both publication manifests

.PHONY: _sign-artifacts
_sign-artifacts:
	@slot='$(KEY_SLOT)'; key='$(SIGNING_KEY)'; \
	if test -z "$$slot"; then printf 'Key slot (a, b, or c): ' >/dev/tty 2>/dev/null && IFS= read -r slot </dev/tty || { echo 'KEY_SLOT is required (non-interactive example: make sign-release-set KEY_SLOT=a)' >&2; exit 2; }; fi; \
	expected=$$($(TOOLS_PYTHON) -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_slots"].get(sys.argv[2].upper(), ""))' "$(ROOT)" "$$slot") || exit $$?; \
	test -n "$$expected" || { echo "Unknown KEY_SLOT: $$slot" >&2; exit 2; }; \
	test -n "$$key" || key="$$expected"; \
	$(TOOLS_PYTHON) scripts/check-signing-key.py "$(ROOT)" "$$slot" "$$key" || exit $$?; \
	slot=$$(printf '%s' "$$slot" | tr 'A-Z' 'a-z'); \
	for artifact in $(SIGN_ARTIFACTS); do \
		test -f "$$artifact" || { echo "Artifact not found: $$artifact" >&2; exit 2; }; \
		./scripts/sign-code.sh "$$artifact" "$$key" "$$artifact.key-$$slot.asc" || exit $$?; \
	done; \
	printf '\nCreated signatures for key slot %s only.\nNext steps:\n  1. Export only the .asc signature file(s); do not export private key material.\n  2. Return the signature(s) to the coordinator with the reviewed SHA-256 values.\n  3. Repeat on the other independent signing stations.\n  4. Run make signing-status to see what remains.\n  5. After collecting A, B, and C, run make verify-publication PUBLICATION_DIR=.\n' "$$slot"

verify-signature: ## Verify detached SIGNATURE over MANIFEST with local GnuPG
	@test -f "$(MANIFEST)" || { echo "Manifest not found: $(MANIFEST)" >&2; exit 2; }
	@test -f "$(SIGNATURE)" || { echo "Signature not found: $(SIGNATURE)" >&2; exit 2; }
	gpg --verify "$(SIGNATURE)" "$(MANIFEST)"

verify-all: ## Verify conventional root, release, and protected publication files
	PYTHONPATH=src $(TOOLS_PYTHON) scripts/verify-publication.py "$(PUBLICATION_DIR)" "$(PUBLIC_KEY_DIR)"

verify-publication: verify-all ## Verify the assembled publication

lab: ## Run the interactive Caretaker lab under caretaker-run
	PYTHONPATH=src:. $(BIN)/python -m caretaker.run --data-directory ./examples/.caretaker-interactive-lab/caretaker-data examples.interactive_caretaker_lab

lab-verified: ## Run lab after verifying the signed source publication
	@test -n "$(TRUSTED_FINGERPRINTS)" || { echo 'TRUSTED_FINGERPRINTS is empty; supply independently confirmed full fingerprints' >&2; exit 2; }
	@args=''; \
	for fingerprint in $(TRUSTED_FINGERPRINTS); do args="$$args --integrity-trusted-fingerprint $$fingerprint"; done; \
	PYTHONPATH=src:. $(BIN)/python -m caretaker.run \
	  --integrity-publication-directory . --integrity-artifact-root . $$args \
	  --data-directory ./examples/.caretaker-interactive-lab/caretaker-data \
	  examples.interactive_caretaker_lab

lab-console: ## Open the Caretaker console for the interactive lab
	PYTHONPATH=src:. $(BIN)/python -m caretaker.console --data-directory ./examples/.caretaker-interactive-lab/caretaker-data

profile: ## Open the Textual Caretaker Profile Editor
	PYTHONPATH=src $(BIN)/python -m caretaker.profile_editor

verify-wheel: wheel ## Install and test the wheel in a temporary virtual environment
	@tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	wheel="dist/caretaker-$(PACKAGE_VERSION)-py3-none-any.whl"; \
	test -f "$$wheel" || { echo "Current-version wheel not found: $$wheel" >&2; exit 1; }; \
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
