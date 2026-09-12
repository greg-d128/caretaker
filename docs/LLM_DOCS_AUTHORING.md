# LLM documentation authoring

The installed `caretaker-docs` bundle is a retrieval aid, not a replacement for
the canonical documentation. Keep cards narrow, independently understandable,
and factual for the current `contract_line`.

## Card structure

Task cards use the required headings in this order: Task, Audience, Status,
Supported package versions, Use when, Do not use when, Prerequisites, Minimal
command or code, Required configuration, Expected result, Verification, Common
failures, Security and scope limitations, Related tasks, and Canonical
documentation. Keep a complete card generally between 300 and 900 tokens.

## Statuses

Use only `implemented`, `experimental`, `operator-only`,
`environment-dependent`, `not-guaranteed`, or `future`. `future` is never a
current implementation claim. Use `environment-dependent` for a supported
capability requiring an external backend, signer, or tool.

## Canonical sources

Every entry records repository-relative canonical source paths. Prefer the
public API inventory and topic documentation over implementation details. A
source path supports a claim; it does not turn an unsigned artifact or an
advisory result into trusted evidence.

## Version updates

Update `index.json` and every reference/card version when the supported package
version or contract line changes. `package_version` must equal
`caretaker.__version__`; `contract_line` changes only after contract review.
Update related links and canonical sources, then run `caretaker-docs index --json`
and the LLM-doc tests. Include package data in both wheel and sdist.

## Token estimates

Estimate each entry deterministically from its UTF-8 Markdown/JSON text using
`ceil(byte_length / 4)`, then round up to the nearest ten. This is a retrieval
budget estimate, not a tokenizer guarantee. Keep estimates bounded and update
them whenever content changes.
