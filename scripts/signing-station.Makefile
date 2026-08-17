PYTHON ?= python3
ROOT ?= root.json

.DEFAULT_GOAL := help
.PHONY: help status check sign-release sign-protected sign-release-set sign-root sign-station-bundle _sign

help:
	@printf '%s\n' \
	  'Offline Caretaker signing station' '' \
	  '  make status                         Show artifacts and missing signatures' \
	  '  make check KEY_SLOT=a               Check this station owns slot A' \
	  '  make sign-release-set KEY_SLOT=a    Sign both release manifests' \
	  '  make sign-root KEY_SLOT=a           Sign root.json when root authorization is needed' \
	  '  make sign-station-bundle KEY_SLOT=a Sign root and both manifests' '' \
	  'KEY_SLOT is the only ordinary input. Its fingerprint comes from root.json.'

status:
	$(PYTHON) signing-status.py . "$(ROOT)"

check:
	@slot='$(KEY_SLOT)'; \
	test -n "$$slot" || { echo 'KEY_SLOT is required, for example: make check KEY_SLOT=a' >&2; exit 2; }; \
	key=$$($(PYTHON) -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_slots"].get(sys.argv[2].upper(), ""))' "$(ROOT)" "$$slot"); \
	test -n "$$key" || { echo "Unknown KEY_SLOT: $$slot" >&2; exit 2; }; \
	$(PYTHON) check-signing-key.py "$(ROOT)" "$$slot" "$$key"

sign-release:
	@$(MAKE) --no-print-directory _sign KEY_SLOT='$(KEY_SLOT)' ARTIFACTS='release-manifest.json'

sign-protected:
	@$(MAKE) --no-print-directory _sign KEY_SLOT='$(KEY_SLOT)' ARTIFACTS='protected-manifest.json'

sign-release-set:
	@$(MAKE) --no-print-directory _sign KEY_SLOT='$(KEY_SLOT)' ARTIFACTS='release-manifest.json protected-manifest.json'

sign-root:
	@$(MAKE) --no-print-directory _sign KEY_SLOT='$(KEY_SLOT)' ARTIFACTS='root.json'

sign-station-bundle:
	@$(MAKE) --no-print-directory _sign KEY_SLOT='$(KEY_SLOT)' ARTIFACTS='root.json release-manifest.json protected-manifest.json'

_sign: check
	@slot=$$(printf '%s' '$(KEY_SLOT)' | tr 'A-Z' 'a-z'); \
	key=$$($(PYTHON) -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_slots"][sys.argv[2].upper()])' "$(ROOT)" "$$slot"); \
	for artifact in $(ARTIFACTS); do \
	  test -f "$$artifact" || { echo "Artifact not found: $$artifact" >&2; exit 2; }; \
	  ./sign-code.sh "$$artifact" "$$key" "$$artifact.key-$$slot.asc" || exit $$?; \
	done; \
	printf '\nCreated signatures for slot %s only. Return the new .asc files and reviewed hashes to the coordinator.\n' "$$slot"
