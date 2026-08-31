PYTHON ?= python3
VENV   ?= venv
BIN     := $(VENV)/bin

ROOT ?= root.json
PUBLICATION_DIR ?= .
PUBLIC_KEYS ?=
PUBLIC_KEY_DIR ?= release-keys
SIGNING_BUNDLE_DIR ?= signing-bundle
# Published Caretaker root identities. Override from an independently trusted
# source when bootstrapping a checkout: make lab-verified TRUSTED_FINGERPRINTS='...'
TRUSTED_FINGERPRINTS ?= 1AA1C739DE9A94B146BD324D335D05E357D334C9 F0F117899E20246935B304D86462FCC9E46C954A F4632C96E4D3C93AE0E894564A9B0D2FBA85B411
WHEEL_MANIFEST_VERSION ?= 1
TOOLS_PYTHON := $(if $(wildcard $(BIN)/python),$(BIN)/python,$(PYTHON))
PACKAGE_VERSION ?= $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml | head -n 1)
ROOT_VERSION ?= $(shell $(TOOLS_PYTHON) -c 'import json; print(json.load(open("$(ROOT)"))["root_version"])' 2>/dev/null)
INTEGRITY := PYTHONPATH=src $(TOOLS_PYTHON) -m caretaker.integrity.cli
TWINE := $(TOOLS_PYTHON) -m twine
PACKAGE_FILES := dist/caretaker-$(PACKAGE_VERSION).tar.gz dist/caretaker-$(PACKAGE_VERSION)-py3-none-any.whl
PYPI_UPLOAD_URL ?= https://upload.pypi.org/legacy/
TEST_PYPI_UPLOAD_URL ?= https://test.pypi.org/legacy/
PODMAN ?= podman
PODMAN_IMAGE ?= localhost/caretaker-replay-base:$(PACKAGE_VERSION)
PODMAN_FAILURE_CORPUS_IMAGE ?= localhost/caretaker-failure-corpus-lab:$(PACKAGE_VERSION)
PODMAN_BASE_IMAGE ?= python:3.13-slim
PODMAN_CGROUP_MANAGER ?= cgroupfs

.DEFAULT_GOAL := help

.PHONY: help setup test compile check wheel podman-image podman-failure-corpus-image podman-verify build package-check verify-wheel publish-testpypi publish-pypi publish-test publish root-check signing-check signing-status signing-bundle release-check release-manifest protected-manifest manifests generate-release-manifest generate-protected-manifest generate-manifests wheel-manifests inspect-integrity sign-check sign-all verify-signature verify-all verify-publication lab lab-verified lab-console profile clean distclean

help: ## Show commands grouped by operator role
	@printf '%s\n' \
	  'Usage: make <command>' '' \
	  'Development:' \
	  '  setup                    Create the development environment' \
	  '  check                    Run tests and compilation checks' \
	  '  build                    Build wheel and source distribution' \
	  '  package-check            Validate current-version distributions with Twine' \
	  '  verify-wheel             Install and test the built wheel' '' \
	  'Isolation:' \
	  '  podman-image             Build the Caretaker rootless replay worker image' \
	  '  podman-failure-corpus-image Build the application laboratory image' \
	  '  podman-verify            Verify rootless Podman and the worker image' '' \
	  'Release coordinator:' \
	  '  release-check            Check root policy, clean source, and release inputs' \
	  '  generate-manifests       Generate release and protected manifests' \
	  '  wheel-manifests          Generate installed-layout manifests after profile signing' \
	  '  inspect-integrity        Display root/manifest metadata and hashes' \
	  '  signing-status           Show missing artifacts, keys, and signatures' \
	  '  signing-bundle           Build the minimal offline-station directory' \
	  '  verify-publication       Verify the assembled three-key publication' \
	  '  publish-testpypi        Upload checked distributions to TestPyPI (CONFIRM=1)' \
	  '  publish-pypi            Upload checked distributions to PyPI (CONFIRM=1)' '' \
	  'Signing station:' \
	  '  signing-check            Verify this station owns KEY_SLOT' \
	  '  sign-check               Check every artifact/signature and identify changes' \
	  '  sign-all                 Sign every missing or changed artifact for KEY_SLOT' '' \
	  'Laboratory:' \
	  '  lab                      Run the interactive Caretaker lab' \
	  '  lab-verified             Run lab after signed release verification' \
	  '  lab-console              Open its operator console' \
	  '  profile                  Open the profile editor' '' \
	  'Advanced: verify-signature, clean, distclean' '' \
	  'Ordinary station example: make sign-check; make sign-all KEY_SLOT=a' \
	  'Run make signing-status at any point to see the next missing step.'

setup: ## Create the development virtual environment
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip build twine pytest cryptography 'textual>=0.80'

test: ## Run tests against the source tree
	PYTHONPATH=src $(BIN)/python -m pytest -q

compile: ## Compile the source, tests, and examples
	$(BIN)/python -m compileall -q src tests examples scripts

check: test compile ## Run source tests and compilation checks

wheel: ## Build the wheel in dist/
	$(BIN)/python -m build --wheel

podman-image: wheel ## Build the Caretaker rootless replay worker image
	@test -n "$(PODMAN_BASE_IMAGE)" || { echo 'PODMAN_BASE_IMAGE must not be empty' >&2; exit 2; }
	case "$(PODMAN_BASE_IMAGE)" in *REVIEWED_DIGEST*) echo 'Replace REVIEWED_DIGEST with a real digest or omit PODMAN_BASE_IMAGE for the local quick-start default' >&2; exit 2;; esac
	case "$(PODMAN_BASE_IMAGE)" in *@sha256:*) ;; *) echo 'Warning: PODMAN_BASE_IMAGE is tag-based; pin it by digest for reviewed or production use.' >&2;; esac
	$(PODMAN) --cgroup-manager="$(PODMAN_CGROUP_MANAGER)" build \
	  --file isolated/podman/Containerfile \
	  --ignorefile isolated/podman/.containerignore \
	  --build-arg "PYTHON_BASE_IMAGE=$(PODMAN_BASE_IMAGE)" \
	  --build-arg "CARETAKER_WHEEL=caretaker-$(PACKAGE_VERSION)-py3-none-any.whl" \
	  --tag "$(PODMAN_IMAGE)" \
	  dist

podman-failure-corpus-image: ## Build the repository-owned application laboratory image
	@test -n "$(PODMAN_BASE_IMAGE)" || { echo 'PODMAN_BASE_IMAGE must not be empty' >&2; exit 2; }
	case "$(PODMAN_BASE_IMAGE)" in *REVIEWED_DIGEST*) echo 'Replace REVIEWED_DIGEST with a real digest or omit PODMAN_BASE_IMAGE for the local quick-start default' >&2; exit 2;; esac
	case "$(PODMAN_BASE_IMAGE)" in *@sha256:*) ;; *) echo 'Warning: PODMAN_BASE_IMAGE is tag-based; pin it by digest for reviewed or production use.' >&2;; esac
	$(PODMAN) --cgroup-manager="$(PODMAN_CGROUP_MANAGER)" build \
	  --file isolated/podman/FailureCorpus.Containerfile \
	  --ignorefile examples/failure_corpus/.containerignore \
	  --build-arg "PYTHON_BASE_IMAGE=$(PODMAN_BASE_IMAGE)" \
	  --tag "$(PODMAN_FAILURE_CORPUS_IMAGE)" \
	  examples/failure_corpus

podman-verify: ## Verify rootless Podman and a previously built worker image
	sh isolated/podman/verify-rootless.sh "$(PODMAN_IMAGE)"

build: ## Build the wheel and source distribution in dist/
	$(BIN)/python -m build

package-check: build ## Validate exactly the current-version wheel and source distribution
	@test -f "dist/caretaker-$(PACKAGE_VERSION).tar.gz" || { echo "Missing source distribution for version $(PACKAGE_VERSION)" >&2; exit 2; }
	@test -f "dist/caretaker-$(PACKAGE_VERSION)-py3-none-any.whl" || { echo "Missing wheel for version $(PACKAGE_VERSION)" >&2; exit 2; }
	$(TWINE) check $(PACKAGE_FILES)
	@echo "Validated distributions for Caretaker $(PACKAGE_VERSION): $(PACKAGE_FILES)"

publish-testpypi: release-check package-check verify-wheel ## Upload the checked package to TestPyPI
	@test "$(CONFIRM)" = 1 || { echo "Refusing TestPyPI upload; rerun with CONFIRM=1" >&2; exit 2; }
	$(TWINE) upload --repository-url "$(TEST_PYPI_UPLOAD_URL)" $(PACKAGE_FILES)
	@echo "Uploaded Caretaker $(PACKAGE_VERSION) to TestPyPI. Next: install it from TestPyPI and smoke-test it before publishing to PyPI."

publish-pypi: release-check package-check verify-wheel ## Upload the checked package to PyPI
	@test "$(CONFIRM)" = 1 || { echo "Refusing PyPI upload; rerun with CONFIRM=1" >&2; exit 2; }
	$(TWINE) upload --repository-url "$(PYPI_UPLOAD_URL)" $(PACKAGE_FILES)
	@echo "Uploaded Caretaker $(PACKAGE_VERSION) to PyPI."

publish-test: publish-testpypi ## Short alias for TestPyPI publication

publish: publish-pypi ## Short alias for PyPI publication

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
	printf '\nResolved slot %s to primary fingerprint %s.\nNext steps:\n  1. Compare the artifact hashes with the coordinator.\n  2. Run make sign-check, then make sign-all KEY_SLOT=%s\n' "$$slot" "$$expected" "$$slot"

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
	printf '\nNext steps:\n  1. Run make inspect-integrity and review both manifests.\n  2. Run make signing-bundle PUBLIC_KEY_DIR=<certificate-directory>.\n  3. Transfer the bundle and run make sign-check, then make sign-all KEY_SLOT=<station-slot>.\n'

inspect-integrity: ## Display root and available manifest metadata and hashes
	$(INTEGRITY) inspect "$(ROOT)"
	@test ! -f release-manifest.json || $(INTEGRITY) inspect release-manifest.json
	@test ! -f protected-manifest.json || $(INTEGRITY) inspect protected-manifest.json

wheel-manifests: ## Generate installed-layout manifests after all profiles are signed
	PYTHONPATH=src $(TOOLS_PYTHON) scripts/generate-wheel-manifests.py \
	  --package-version "$(PACKAGE_VERSION)" --manifest-version "$(WHEEL_MANIFEST_VERSION)" $(if $(filter 1,$(FORCE)),--force,)

sign-check: ## Verify every release artifact signature and identify changed bytes
	$(TOOLS_PYTHON) scripts/sign-artifacts.py check --directory "$(PUBLICATION_DIR)" --root "$(ROOT)" --public-key-dir "$(PUBLIC_KEY_DIR)"

sign-all: ## Sign missing or changed release artifacts for one key slot
	@slot='$(KEY_SLOT)'; \
	if test -z "$$slot"; then printf 'Key slot (a, b, or c): ' >/dev/tty 2>/dev/null && IFS= read -r slot </dev/tty || { echo 'KEY_SLOT is required (example: make sign-all KEY_SLOT=a)' >&2; exit 2; }; fi; \
	$(MAKE) --no-print-directory signing-check KEY_SLOT="$$slot" SIGNING_KEY="$(SIGNING_KEY)" || exit $$?; \
	$(TOOLS_PYTHON) scripts/sign-artifacts.py sign --directory "$(PUBLICATION_DIR)" --root "$(ROOT)" --public-key-dir "$(PUBLIC_KEY_DIR)" --key-slot "$$slot" $(if $(SIGNING_KEY),--signing-key "$(SIGNING_KEY)",)

generate-release-manifest: release-manifest ## Generate the ordinary release manifest

generate-protected-manifest: protected-manifest ## Generate the protected-code manifest

generate-manifests: manifests ## Generate both publication manifests

verify-signature: ## Verify detached SIGNATURE over MANIFEST with local GnuPG
	@test -f "$(MANIFEST)" || { echo "Manifest not found: $(MANIFEST)" >&2; exit 2; }
	@test -f "$(SIGNATURE)" || { echo "Signature not found: $(SIGNATURE)" >&2; exit 2; }
	gpg --verify "$(SIGNATURE)" "$(MANIFEST)"

verify-all: ## Verify conventional root, release, and protected publication files
	PYTHONPATH=src $(TOOLS_PYTHON) scripts/verify-publication.py "$(PUBLICATION_DIR)" "$(PUBLIC_KEY_DIR)"

verify-publication: verify-all ## Verify the assembled publication

lab: ## Run the interactive Caretaker lab under caretaker-run
	PYTHONPATH=src:. $(BIN)/python -m caretaker.run --profile sandbox --data-directory ./examples/.caretaker-interactive-lab/caretaker-data examples.interactive_caretaker_lab

lab-verified: ## Run lab after verifying the signed source publication
	@test -n "$(TRUSTED_FINGERPRINTS)" || { echo 'TRUSTED_FINGERPRINTS is empty; supply independently confirmed full fingerprints' >&2; exit 2; }
	@args=''; \
	for fingerprint in $(TRUSTED_FINGERPRINTS); do args="$$args --integrity-trusted-fingerprint $$fingerprint"; done; \
	PYTHONPATH=src:. $(BIN)/python -m caretaker.run \
	  --integrity-publication-directory . --integrity-artifact-root . $$args \
	  --profile sandbox \
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
	"$$tmp/venv/bin/caretaker-integrity" verify-install || exit $$?; \
	"$$tmp/venv/bin/python" -m pytest -q -m "not repository" tests

clean: ## Remove generated build and test files
	rm -rf build dist .pytest_cache
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +

distclean: clean ## Also remove the development virtual environment
	rm -rf $(VENV)
