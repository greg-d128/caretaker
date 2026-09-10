# Caretaker 0.6.5 independent validation handoff

This document defines the evidence an independent validator should collect for
Caretaker 0.6.5. It is a handoff procedure, not a claim that Validator or
Crucible has already certified this checkout. The external run must use the
same source revision and explicitly identified artifacts; a Caretaker test
that imports the source tree is not an independent oracle.

## Caretaker-side artifact identity

From a clean Caretaker checkout, record the source revision and environment:

```bash
git rev-parse HEAD
git status --short
python --version
```

Build and check the exact current-version artifacts:

```bash
make check
make package-check
sha256sum dist/caretaker-0.6.5.tar.gz \
  dist/caretaker-0.6.5-py3-none-any.whl
```

The validator must receive these exact files and the recorded hashes. Do not
replace them with a similarly named wheel from a prior alpha or a different
source revision. `make verify-wheel` is a separate signed-publication gate; it
must remain fail-closed until the release station regenerates and signs the
0.6.5 installed-layout manifests.

## Required independent runtime proof

Using a fresh environment and the exact wheel, prove the real installed
entrypoint rather than only importing internal classes:

1. Install the wheel without resolving a different Caretaker version.
2. Launch `caretaker-run` with an importable probe application and an explicit
   policy.
3. Query the authenticated control socket after readiness and record the
   supervisor, writer, event-server, and control-server workers.
4. Confirm the configured application identity reaches the child process.
5. Confirm normal application exit removes the events, control, and runtime
   sockets.
6. Repeat with a missing application module and confirm a nonzero startup
   result and removal of all three endpoints.

The source-tree regression equivalent is
`tests/test_run_entrypoint.py`. The independent run must preserve its own
oracle: the probe application and cleanup checks must not call Caretaker
internals to report success.

## Validator handoff

In `../caretaker_validation`, select the exact wheel through the repository's
documented wheel configuration, then run the normal campaign checks in a clean
environment:

```bash
make campaign-plan
make setup
make doctor
make check
```

Run the focused lifecycle, worker-recovery, Python-compatibility, and
container-enforcement targets when their declared prerequisites are available.
If Podman is unavailable, report the skipped container execution and retain
the command-boundary evidence; do not convert a skipped backend run into a
pass. The Validator catalog and configuration must be updated to the current
0.6.5 artifact before a formal campaign is called current. A configuration
still naming 0.6.5a or a wheel from `/tmp` is not evidence for this release.

## Crucible handoff

In an environment that does not import Caretaker's source tree, install the
same wheel and run the Crucible's independent doctor, plan, coverage, and
execution workflow against the current profile/catalog. Record the exact
commands and their output. Crucible must retain its own oracles and must not
turn Caretaker's reported status into the pass/fail decision.

The current Crucible and Validator checkouts contain older release references;
that is a coordination item for the independent-validation owners. This
repository does not modify sibling repositories as part of a Caretaker release
change. Until their catalog/profile references identify 0.6.5 explicitly, the
external validation status is pending rather than complete.

## Evidence record

Every independent result should include:

- source commit and wheel/sdist SHA-256 values;
- Python version, operating system, and relevant backend versions;
- selected profile/catalog and its version or fingerprint;
- exact commands, pass/fail/skip result, and retained logs;
- whether the installed wheel or source distribution was tested;
- container image identity and digest when container tests run;
- any environmental limitation, especially unavailable Podman or unsigned
  release-station material.

## Invariant map

This map directs reviewers to implementation and local regression evidence. It
is not a substitute for the independent run.

| Invariant | Implementation areas | Local evidence |
| --- | --- | --- |
| Caretaker cannot grant itself authority | `authority.py`, policy composition, runtime leases | authority and policy-authority tests |
| Failed validation cannot authorize repair | validation boundary and repair admission | `test_validation_trust_boundary.py`, security regressions |
| Terminal workers remain terminal and restarts are bounded | runtime supervision and worker packets | worker-failure, lifecycle, and entrypoint tests |
| IPC endpoints have one owner and safe cleanup | logging/control IPC and supervisor shutdown | logging IPC supervisor tests, entrypoint test |
| Rooted stores cannot follow symlinks or exceed limits | store, capsule, replay, and container validation | store, capsule, resource, and container tests |
| Artifacts retain provenance and identity | behavior, capsule, communication, and replay stores | behavior, capsule, and communication tests |
| Provider output remains advisory | provider transport and repair authority boundary | provider/security and repair tests |
| Audit events remain evidence, not authority | audit registry and runtime event projection | audit registry and logging audit tests |

