# Security policy

Caretaker is alpha research software. It provides no guarantee of correctness, availability, containment, recovery, or security, and it should not be the sole control protecting production software or evidence.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to `grzegorz@beyondparnoia.org`. Include the affected revision or version, configuration, reproduction steps, impact, and whether disclosure is time-sensitive. Do not include secrets, production evidence, personal data, private keys, or exploit data belonging to systems you do not control.

Use the public issue tracker for ordinary bugs and already-public hardening work. Do not open a public issue for a previously undisclosed vulnerability until the maintainer has had a reasonable opportunity to assess it.

There is currently no response-time or remediation SLA. Receipt, impact, applicability, and a disclosure plan will be coordinated on a best-effort basis appropriate for a research project.

## Supported versions and platforms

Security work currently targets the `main` development branch and the latest published alpha. Older alpha releases may be retained for research history but should not be assumed to receive fixes.

The declared Python versions are CPython 3.11, 3.12, and 3.13. The primary platform is Linux. Unix-domain control sockets, `/proc` and `/sys` collection, peer credentials, rootless Podman, Multipass, and GnuPG behavior are platform-dependent. Other operating systems and Python implementations are not currently claimed as supported security environments.

## Known limitations

The public limitation ledger is [`docs/FUTURE_WORK.md`](docs/FUTURE_WORK.md). Strict expected-failure security regressions are retained in `tests/test_validation_trust_boundary.py` and `tests/test_security_assurance_regressions.py`. These are known debts, not hidden guarantees.

Particularly important boundaries include same-UID administrative control, trusted validation backends and pickle transport, process-local Repair state, Python-level Guard visibility, locally replaceable evidence, and operator-overridable validation isolation.
