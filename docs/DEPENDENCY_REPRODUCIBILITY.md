# Dependency reproducibility

Caretaker keeps library-friendly lower bounds in `pyproject.toml`; installing
Caretaker does not impose this repository's development or release toolchain.
Release verification uses an independently reviewed constraints snapshot so a
source-tree or wheel result can be reproduced against the same resolved
environment.

## Supported and verified matrix

| Interpreter | Declared status | Current evidence |
| --- | --- | --- |
| CPython 3.11 | Supported | Forgejo CI target; rerun the release gates before publication |
| CPython 3.12 | Supported | Forgejo CI target; rerun the release gates before publication |
| CPython 3.13 | Supported | Forgejo CI target; rerun the release gates before publication |
| CPython 3.14 | Supported | 3.14.4 review environment: full source suite and package build passed |

The current snapshot is
`constraints/caretaker-0.6.5-py3.14.txt`. It records the complete resolved
development/signing/release environment observed by `pip freeze --all`,
including the runtime dependency `textual` and optional signing dependency
`cryptography`. It is a verification input, not a runtime pin.

## Reproducing a verification environment

Create a fresh virtual environment for the selected interpreter, install the
development and signing tools, and constrain the installation with the
matching snapshot when one exists:

```bash
python3.14 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install --constraint \
  constraints/caretaker-0.6.5-py3.14.txt \
  'textual>=0.80' 'pytest>=8' 'build>=1' 'twine>=5' 'cryptography>=42'
PYTHONPATH=src venv/bin/python -m pytest -q
venv/bin/python -m build
```

The command must be run again for each supported interpreter. A passing
3.14 snapshot does not prove compatibility on 3.11–3.13.

## Updating the snapshot

After a deliberate dependency review, refresh the selected environment with:

```bash
venv/bin/python -m pip freeze --all | sort
```

Replace only the corresponding interpreter snapshot, update its Python and
platform header, run the full source and installed-wheel gates, and record the
exact interpreter and constraints file in the verification report. Review
transitive changes for security and compatibility; do not silently turn a
constraints update into a runtime lower-bound change.

Newer dependency versions should be tested periodically without overwriting
the reproducible snapshot first. This separates compatibility discovery from
the exact environment used to support a release claim.
