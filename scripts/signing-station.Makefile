PYTHON ?= python3
ROOT ?= root.json

.DEFAULT_GOAL := help
.PHONY: help status check sign-check sign-all

help:
	@printf '%s\n' \
	  'Offline Caretaker signing station' '' \
	  '  make status                         Show legacy publication progress' \
	  '  make check KEY_SLOT=a               Check this station owns slot A' \
	  '  make sign-check                     Verify every artifact and signature' \
	  '  make sign-all KEY_SLOT=a            Sign all missing or changed artifacts' '' \
	  'KEY_SLOT is the only ordinary input. Its fingerprint comes from root.json.'

status:
	$(PYTHON) signing-status.py . "$(ROOT)"

check:
	@slot='$(KEY_SLOT)'; \
	test -n "$$slot" || { echo 'KEY_SLOT is required, for example: make check KEY_SLOT=a' >&2; exit 2; }; \
	key=$$($(PYTHON) -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_slots"].get(sys.argv[2].upper(), ""))' "$(ROOT)" "$$slot"); \
	test -n "$$key" || { echo "Unknown KEY_SLOT: $$slot" >&2; exit 2; }; \
	$(PYTHON) check-signing-key.py "$(ROOT)" "$$slot" "$$key"

sign-check:
	$(PYTHON) sign-artifacts.py check

sign-all:
	@slot='$(KEY_SLOT)'; \
	test -n "$$slot" || { echo 'KEY_SLOT is required, for example: make sign-all KEY_SLOT=a' >&2; exit 2; }; \
	$(MAKE) --no-print-directory check KEY_SLOT="$$slot" || exit $$?; \
	$(PYTHON) sign-artifacts.py sign --key-slot "$$slot"
