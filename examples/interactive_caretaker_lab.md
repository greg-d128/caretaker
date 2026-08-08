# Interactive Caretaker Behavior Lab

`interactive_caretaker_lab.py` is a terminal-driven laboratory for exploring
Caretaker one behavior at a time. It is intended for developers who want to
observe what Caretaker records, how Guard reacts to behavioral changes, how
Repair handles failures, and how runtime modification appears in the evidence.

The lab is deliberately interactive. Run one experiment, inspect the evidence,
restore the target, and then move on to the next experiment.

## Quick start

From the repository root:

```bash
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab
```

This is the easiest way to begin. The program creates its own working directory
under:

```text
./caretaker-interactive-lab/
```

No Internet access is required. The example starts local loopback HTTP servers
for the webpage and API tests.

> **Do not enter real passwords, API keys, tokens, or other sensitive data.**
> The lab intentionally enables argument and result evidence so that you can
> inspect what Caretaker records.

## Recommended first experiment

A useful first session is the division target because it demonstrates input
errors, output validation, Repair, operator approval, and FunctionSlot changes.

1. Start the lab.
2. Select **1. Divide two values**.
3. Accept the defaults `10` and `2`.
4. Select **10. Inspect Caretaker / Guard / logs / console**.
5. Look at:
   - **5. Show recent Guard events**
   - **9. Show recent Repair events**
   - **13. Show recent Caretaker log records**
6. Return to the main menu.
7. Select **9. Modify / inject function implementations**.
8. Choose **1. Change behavior substitution**.
9. Select the division target and change it to **bad**.
10. Run **Divide two values** again with `10` and `2`.
11. Inspect **Repair events** and **pending Repair approvals**.
12. Approve or reject the pending repair and run the target again.
13. Restore the target before beginning another experiment.
Also try division inputs such as:
```text
5       0
9       3
monkey  wrench
10      banana
```
The point is not merely whether the call succeeds. Compare the application
exception, Guard evidence, Repair events, FunctionSlot state, and logged data.
## Guard experiment
To explore behavioral drift separately from ordinary bad input:

1. Run a target using its **benign** implementation.
2. Open the inspection menu and select **3. Accept Guard baseline for a target**.
3. Open the modification menu.
4. Select **1. Change behavior substitution** and choose **malicious**.
5. Run the same target again.
6. Inspect:
   - Guard behavior summary;
   - recent Guard events;
   - Guard deviations;
   - Guard decisions;
   - the synthetic loopback collector.
7. Restore the target when finished.

The contained `malicious` variants may perform unrelated filesystem,
subprocess, and loopback-network activity so that Guard has something obvious
to observe. They are intentionally constrained to the laboratory workspace and
loopback interfaces.

## Runtime tampering experiment

Behavior substitution changes what the stable dispatcher calls. It does not
itself modify the active Caretaker FunctionSlot implementation.

To simulate an unauthorized runtime code change instead:

1. Run a target normally.
2. Open **Modify / inject function implementations**.
3. Select **2. Mutate the active dispatcher's `__code__` object**.
4. Choose a target and alternate implementation.
5. Run the target again.
6. Open the inspection menu.
7. Select **7. Show Guard runtime inspections / code changes**.

This experiment is useful for seeing the difference between a change in
application behavior and a direct mutation of a Python code object.

The modification menu also provides **direct FunctionSlot injection**. This is
an intentionally out-of-band operation that bypasses the normal Repair provider
and validation pipeline so that you can examine Caretaker's runtime state after
an unexpected implementation replacement.

## Targets and useful inputs

| Target | Things to try |
| --- | --- |
| Divide two values | `10 / 2`, `5 / 0`, `monkey / wrench`, numeric strings |
| List a directory | default workspace, `.`, nonexistent directory, a filename instead of a directory |
| Load a webpage | default `/page`, `/pag`, `/missing`, bad port, optionally an external URL |
| Search file contents | `caretaker`, `banana`, nonexistent word, nonexistent directory, binary/unreadable files |
| Call a JSON API | `/api/status`, `/api/echo`, `/api/stats`, missing leading slash, bad port |
| Transform text | ordinary text, numbers, punctuation, empty input |
| Write a note | `notes/test.txt`, `nested/deeper.txt`, `../escape.txt` |
| Soft timeout | `0.10`, `0.75`, invalid numeric input |

Each target displays more specific ideas immediately before asking for its
parameters.

## Understanding the three implementation changes

The modification menu deliberately exposes three different mechanisms because
they test different Caretaker behaviors.

### Behavior substitution

The stable Caretaker target remains unchanged, but its dispatcher calls a
benign, bad, or suspicious alternate implementation.

Use this primarily for:

- application defects;
- incorrect results;
- behavioral drift;
- additional resource activity observed by Guard.

### Code-object mutation

The target's active Python `__code__` object is replaced directly.

Use this for:

- simulated runtime tampering;
- Guard runtime inspection;
- comparing code identity with behavioral evidence.

### FunctionSlot injection

An alternate implementation is inserted directly into the Caretaker
FunctionSlot.

Use this for:

- examining FunctionSlot versions and state;
- simulated out-of-band activation;
- rollback and probation experiments.

This deliberately bypasses the normal candidate-generation and validation path.
It is a laboratory control, not an example of how an application should deploy
repairs.

## Inspecting Caretaker

The inspection menu provides several complementary views. In particular:

- **FunctionSlot and behavior state** shows which implementation is currently
  active and whether you changed the dispatcher or slot.
- **Effective target policy** shows the Repair, Logging, Guard, and retry policy
  actually attached to the target.
- **Guard events** show observed filesystem, network, subprocess, and other
  resource activity.
- **Guard deviations** show comparisons against accepted behavior baselines.
- **Runtime inspections** are particularly useful after `__code__` mutation.
- **Repair events** show incidents, candidate validation, approval, activation,
  retry, and rollback activity.
- **Pending approvals** allow you to approve or reject repairs interactively.
- **Caretaker log records** show persisted application evidence.
- **Python console** exposes the live `ENGINE`, `GUARD`, targets, variants, and
  FunctionSlots for deeper examination.

The Python console runs with the same OS privileges as the application. Treat it
as a developer debugging facility, not a security boundary.

## Running under the Caretaker supervisor

For experiments involving the local control socket, start the example with the
Caretaker supervisor:

```bash
PYTHONPATH=src:. python -m caretaker.run \
  --data-directory ./caretaker-interactive-lab/caretaker-data \
  examples.interactive_caretaker_lab
```

Then select:

```text
10. Inspect Caretaker / Guard / logs / console
```

The lab prints the actual control-socket path and useful commands for another
terminal.

## Files created by the lab

By default, everything created by the example is placed below:

```text
./caretaker-interactive-lab/
```

Important subdirectories are:

```text
caretaker-interactive-lab/
├── caretaker-data/     Caretaker logs and runtime evidence
└── workspace/          Synthetic files used by the experiments
```

You can place the lab somewhere else by setting `CARETAKER_LAB_ROOT` before
startup:

```bash
CARETAKER_LAB_ROOT=/tmp/my-caretaker-lab \
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab
```

The example does not recursively delete the workspace on startup because you
may intentionally add test files while experimenting.

## Safety notes

The built-in suspicious implementations are designed for observation, not for
damage. They are limited to laboratory-owned files, a fixed harmless child
process, and loopback HTTP traffic. The synthetic collector receives a digest,
not arbitrary user file contents.

However, some menu options allow *you* to enter paths and URLs. If you enter a
real directory or an external URL, the application will attempt to operate on
what you supplied, subject to the target's own checks. For a clean demonstration,
use the default workspace and loopback endpoints first.

The example also exposes deliberate runtime mutation controls and an interactive
Python console. Run it only in a development/test environment.

## A useful testing rhythm

For most experiments, use this sequence:

```text
Run benign target
    -> inspect
    -> optionally accept Guard baseline
    -> make one change
    -> run again
    -> inspect Guard / Repair / logs
    -> approve, reject, or roll back as appropriate
    -> restore target
    -> move to next experiment
```

Changing only one thing at a time makes Caretaker's response much easier to
understand.
