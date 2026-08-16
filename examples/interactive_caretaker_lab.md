# Interactive Caretaker Behavior Lab

`interactive_caretaker_lab.py` is a Textual application for driving one
Caretaker experiment at a time. The lab changes application inputs and
implementations; the **standard Caretaker console** is used from a second
terminal to inspect what happened.

```text
Terminal 1: Textual lab               Terminal 2: caretaker-console
-----------------------               -----------------------------
choose a target                       watch runtime status
enter parameters                      inspect Guard evidence
execute the target                    inspect Repair events
substitute/inject behavior            approve or reject repairs
restore the target                    inspect logs / ask Guard LLM
```

The separation is intentional. Application controls stay in the example while
operator controls stay in Caretaker itself.

> The lab records selected function arguments and exception evidence. Do not
> enter real passwords, API keys, tokens, or other sensitive information.

## Quick start

Run the lab under the Caretaker supervisor so the operator console can inspect
its live Repair and Guard objects:

```bash
PYTHONPATH=src:. python -m caretaker.run \
  --data-directory ./examples/.caretaker-interactive-lab/caretaker-data \
  examples.interactive_caretaker_lab
```

The lab itself opens as a Textual UI.

In a second terminal, attach the standard Caretaker console:

```bash
PYTHONPATH=src:. python -m caretaker.console \
  --data-directory ./examples/.caretaker-interactive-lab/caretaker-data
```

After installation the shorter command is:

```bash
caretaker-console \
  --data-directory ./examples/.caretaker-interactive-lab/caretaker-data
```

The console status line continuously reports information such as:

```text
Status HEALTHY | Alert NONE | Incidents 0 | Validating 0 |
Approvals 0 | Targets 8 | Worker issues 0
```

When Caretaker is actively processing a failure you can see the status change to
states such as `INCIDENT_ACTIVE`, `VALIDATING`, or `AWAITING_APPROVAL`.

## Lab UI

The left side selects one of eight application targets. The main panel shows:

- a breadcrumb showing the current target/action;
- a short list of ideas worth trying;
- editable function arguments;
- the currently selected behavior and FunctionSlot state;
- an **Execute function** action;
- controls for benign/bad/malicious implementation experiments;
- a local result/error log.

The lab deliberately does not duplicate Guard, Repair, approval, or logging
screens. Those belong to `caretaker-console`.

## Recommended first experiment

### 1. Establish normal division behavior

In the lab select **Divide two values** and execute the defaults:

```text
10
2
```

In `caretaker-console`:

1. Open the **Guard** tab.
2. Enter `lab.divide` as the target.
3. View **Events** and **Summary**.
4. Select **Accept baseline**.

### 2. Introduce a bad implementation

Back in the lab:

1. Select **Bad**.
2. Select **Substitute behavior**.
3. Execute division again with `10` and `2`.

The bad implementation returns the wrong type, causing output validation to
fail and opening a Repair episode.

In `caretaker-console`:

1. Watch the status line for incident/validation activity.
2. Open **Repair** and select **Events**.
3. Select **Approvals**.
4. Copy the pending episode UUID into the episode field.
5. Select **Approve**.

Run division again and inspect the target/runtime state.

Also try inputs such as:

```text
5       0
9       3
monkey  wrench
10      banana
```

These demonstrate the difference between bad input and a bad implementation.

## Guard behavioral-drift experiment

1. Restore a target to benign behavior.
2. Run it once or more.
3. In the Caretaker console, accept its Guard baseline.
4. In the lab select **Malicious** and **Substitute behavior**.
5. Run the target again.
6. In the Caretaker console inspect:
   - Guard events;
   - deviations;
   - runtime inspections;
   - Guard decisions;
   - Repair events where applicable.

The contained malicious variants intentionally add unrelated filesystem,
subprocess, and loopback-network activity so Guard has obvious new behavior to
observe.

## Runtime tampering experiment

The lab exposes three different implementation-change mechanisms because they
test different Caretaker boundaries.

### Substitute behavior

The stable Caretaker target remains unchanged, but its dispatcher calls another
implementation.

Use this for:

- application bugs;
- wrong results;
- new resource behavior;
- Guard baseline/deviation experiments.

### Mutate `__code__`

The active dispatcher's Python `__code__` object is replaced directly without
calling Caretaker Repair.

Use this for:

- simulated unauthorized in-process mutation;
- Guard runtime inspection;
- code-identity vs. behavioral evidence comparisons.

After mutation, execute the target and inspect **Guard > Inspections** in the
Caretaker console.

### Inject FunctionSlot

An alternate implementation is inserted directly into the FunctionSlot,
deliberately bypassing candidate generation and validation.

Use this for:

- FunctionSlot version/state inspection;
- out-of-band activation simulations;
- rollback/probation experiments.

This is a lab control, not a supported repair deployment path.

## Targets and useful inputs

| Target | Things to try |
| --- | --- |
| Divide two values | `10 / 2`, `5 / 0`, `monkey / wrench`, numeric strings |
| List a directory | default workspace, `.`, nonexistent directory, a filename |
| Load a webpage | default `/page`, `/pag`, `/missing`, bad port |
| Search file contents | `caretaker`, `banana`, nonexistent word/directory |
| Call a JSON API | `/api/status`, `/api/echo`, `/api/stats`, bad port |
| Transform text | ordinary text, numbers, punctuation, empty input |
| Write a note | `notes/test.txt`, `nested/deeper.txt`, `../escape.txt` |
| Soft timeout | `0.10`, `0.75`, invalid numeric input |

The webpage/API targets use loopback-only demo servers, so Internet access is
not required.

## LLM-assisted investigation

The Caretaker console's **Guard > LLM assist** action asks the running Guard
engine for an advisory assessment of the selected target's evidence.

This is available only when the application configured a Guard assessment
provider and enabled LLM review. The console does not silently create a remote
provider or transmit evidence merely because the button was selected.

LLM output is advisory. It does not authorize Repair, override deterministic
validation gates, or override Integrity policy.

## What to watch in the Caretaker console

The most useful observations are:

- **status line**: incident, validation, approval, alert, and worker state;
- **Overview**: registered targets, Repair mode/authority, FunctionSlot version;
- **Guard / Events**: resource activity correlated to target calls;
- **Guard / Deviations**: behavior compared with an accepted baseline;
- **Guard / Inspections**: runtime/code changes;
- **Repair / Events**: incident, generation, validation, activation, retry;
- **Repair / Approvals**: candidates waiting for explicit operator action;
- **Logs**: persisted Caretaker/application evidence.

A useful discipline is to make **one change, run one target, inspect evidence,
then restore it** before trying the next experiment.

## Safety boundary

The `malicious` variants are deliberately contained simulations. They:

- read only a synthetic secret created inside the lab workspace;
- write only lab-owned marker files;
- run a fixed harmless Python child process without `shell=True`;
- send only a SHA-256 digest to a second loopback-only HTTP server;
- do not delete arbitrary user files;
- do not intentionally transmit data off-host.

The lab keeps generated state beside the example source rather than in the
repository root. The entire runtime directory is ignored by Git. The workspace
defaults to:

```text
./examples/.caretaker-interactive-lab/workspace
```

The Caretaker data directory used by the commands above is:

```text
./examples/.caretaker-interactive-lab/caretaker-data
```

The complete lab root can be moved with:

```bash
CARETAKER_LAB_ROOT=/some/test/path ...
```

If an older version of the example created `./caretaker-interactive-lab` in the
repository root, this change does not move or delete it. Preserve it if you need
the old evidence; otherwise it can be removed manually after the new lab is
running from `examples/.caretaker-interactive-lab`.

Use a disposable development environment when experimenting with runtime code
mutation and FunctionSlot injection.

### Optional Guard LLM assessment in the lab

To make the console's **Guard > LLM assist** action available for this example,
start the supervised lab with a local Ollama model name:

```bash
CARETAKER_LAB_OLLAMA_MODEL=gemma3:27b \
PYTHONPATH=src:. python -m caretaker.run \
  --data-directory ./examples/.caretaker-interactive-lab/caretaker-data \
  examples.interactive_caretaker_lab
```

The example uses Caretaker's loopback-only Ollama provider defaults. If the
environment variable is absent, Guard LLM review remains disabled and selecting
**LLM assist** reports that no advisory provider is configured.
