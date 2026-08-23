# AGENTS.md

## Purpose

This repository contains the canonical Caretaker implementation.

Caretaker is currently an application-scoped, policy-constrained self-repair system. The current implementation must remain within the authority of the application in which it is integrated. Host-level and infrastructure-level Caretaker concepts are future work unless the user explicitly asks to implement them.

## Working rules

- Treat this repository as the source of truth for Caretaker behavior, public APIs, policy semantics, signing behavior, schemas, examples, and release artifacts.
- Keep changes narrowly scoped. Do not bundle unrelated cleanup with the requested work.
- Preserve existing architecture unless a change clearly requires modifying it.
- Prefer the smallest implementation that satisfies the requested behavior.
- Do not add dependencies without a clear need.
- Infer local conventions from the code and tests before editing.
- Distinguish facts observed in the repository or test output from inference and recommendations.
- Do not silently change public behavior, defaults, policy meaning, signing rules, artifact formats, or security guarantees.

## Security and authority invariants

Caretaker's trust model is part of the product.

Preserve these principles unless the task explicitly changes the design:

- Caretaker must not grant itself authority.
- LLM reasoning does not create authority.
- Failed validation must not be bypassed merely because a repair appears convincing.
- Repair must remain constrained by the configured policy and authority boundary.
- A repair must not silently modify the policy that governs its own authorization or validation.
- Signed artifacts and policy material must be verified according to the repository's current rules.
- Unknown or untrusted code, evidence, or artifacts must not become trusted merely because another component presents them.
- The current application-level Caretaker must not require new host or superuser privileges.

When working on security-sensitive code, prefer explicit failure over ambiguous fallback behavior.

## Scope

Current implementation scope:

- Application observation and instrumentation.
- Incident detection.
- Evidence collection.
- Diagnosis and hypothesis generation.
- Policy-constrained repair.
- Validation.
- Continued observation after intervention.
- Signed distribution, policy, and related authority mechanisms implemented by the repository.

Future concepts such as Host Caretaker, Infrastructure Caretaker, post-mortem replay, or other roadmap items must remain future work unless explicitly requested.

## Tests

- Run the most specific relevant tests first.
- Before declaring a change complete, run the repository's normal validation targets when practical.
- Inspect the current `Makefile`, project metadata, and test configuration rather than assuming command names.
- A failing test is evidence. Determine whether the implementation or the test is wrong before changing either.
- Add regression tests for bugs and security guarantees when practical.
- Tests must remain local and non-destructive. Do not target third-party systems.

For security work, prefer tests that state the intended invariant clearly.

## Documentation

Documentation is part of the implementation contract.

When behavior changes, check whether the change affects:

- README and getting-started material.
- Architecture and design documents.
- Policy documentation.
- Signing and release documentation.
- Examples.
- Future-work documentation.
- Website-facing claims.

Do not describe planned functionality as currently implemented.

## Release and packaging

When changing packaging, release metadata, signing, profiles, wheel contents, or installation behavior:

- Treat release artifacts as security-sensitive.
- Keep package metadata accurate.
- Ensure only intended reviewable material is included in signing bundles and release artifacts.
- Preserve validation of signed profiles and other protected artifacts.
- Check downstream impact on `caretaker-validation` and `caretaker-crucible`.

## Cross-repository impact

If sibling repositories are available, significant changes should be assessed for downstream effects:

- `../caretaker-validation`
- `../caretaker-crucible`
- the Caretaker website repository

Do not modify sibling repositories unless the task explicitly includes cross-repository work. Instead, report required downstream changes clearly.

## Patch and diff workflow

When producing multiple diffs or patches for Caretaker work, prepend a sequential number to each diff so application order is unambiguous.

## Commit and push workflow

Bias toward completing each conceptual unit of work as a separate commit.

After a coherent change is implemented and relevant tests pass:

1. review the diff;
2. ensure unrelated changes are not included;
3. commit the completed conceptual unit with a concise, accurate message;
4. push the commit to the configured remote when credentials and repository policy permit it.

Do not combine unrelated conceptual units merely to reduce commit count.

Do not commit or push:
- known-broken work;
- unrelated local changes;
- generated secrets, credentials, or private material;
- changes outside the requested scope;
- work when the user explicitly asks to leave changes uncommitted.

If pushing is unavailable or blocked, commit locally when appropriate and report the push limitation clearly.

## Completion

A change is complete when:

- The requested behavior is implemented.
- Relevant tests pass or remaining failures are explained.
- Security and authority guarantees remain intact.
- Documentation affected by the change is updated.
- Any downstream repository impact is identified.
