# Interactive Caretaker Behavior Lab

`interactive_caretaker_lab.py` is a terminal-driven laboratory for exploring
Caretaker one behavior at a time. The application menu is intentionally limited
to **driving application behavior**. Observation and operator interaction happen
from a second terminal through the lab console.

This separation makes experiments easier to follow:

```text
Terminal 1: application menu       Terminal 2: Caretaker lab console
----------------------------       -------------------------------
run a function                     inspect Guard events
change an implementation           inspect Repair events
run the function again             compare deviations/inspections
restore the function               accept baselines / approve repairs
```

The lab is intended for development and testing. Run one experiment, inspect the
evidence, restore the target, and then move to the next experiment.

## Quick start

From the repository root, start the application in the first terminal:

```bash
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab
```

The program creates its own working directory under:

```text
./caretaker-interactive-lab/
```

No Internet access is required. The example starts local loopback HTTP servers
for the webpage and API tests.

In a **second terminal**, attach the lab console:

```bash
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab_console
```

You should see something similar to:

```text
Caretaker interactive lab console
Attached to: .../caretaker-data/run/lab-console.sock
Lab PID: 12345  supervised=False
Type 'help' for commands; 'quit' to disconnect.
caretaker-lab>
```

Then type:

```text
help
```

> **Do not enter real passwords, API keys, tokens, or other sensitive data.**
> The lab intentionally enables argument and result evidence so you can inspect
> what Caretaker records.

## Menu breadcrumbs

Every application menu shows where you are. For example:

```text
[Caretaker Lab > Main]
Application behavior menu
```

and:

```text
[Caretaker Lab > Main > Modify implementations]
Implementation modification menu
```

Target and variant-selection menus continue the breadcrumb. This is especially
useful while repeatedly moving between execution and modification experiments.

## Recommended first experiment

Division is a useful first target because it demonstrates input errors, output
validation, Repair, operator approval, and FunctionSlot changes.

### Terminal 1: establish normal behavior

1. Start the lab.
2. Select **1. Divide two values**.
3. Accept the defaults `10` and `2`.

### Terminal 2: inspect the normal call

At the lab console:

```text
state lab.divide
events lab.divide
repair lab.divide
```

Accept the current Guard behavior as a baseline:

```text
baseline lab.divide
```

### Terminal 1: introduce a defect

1. Select **9. Modify / inject function implementations**.
2. Select **1. Change behavior substitution**.
3. Select the division target.
4. Select **bad**.
5. Run division again with `10` and `2`.

### Terminal 2: examine Caretaker's response

```text
state lab.divide
events lab.divide
deviations lab.divide
repair lab.divide
approvals
```

If a Repair episode is awaiting approval, copy its episode ID and approve it:

```text
approve <episode-id>
```

Then rerun the division target in Terminal 1 and inspect the state again:

```text
state lab.divide
repair lab.divide
```

Also try division inputs such as:

```text
5       0
9       3
monkey  wrench
10      banana
```

The point is not merely whether the call succeeds. Compare the application
exception, Guard evidence, Repair events, FunctionSlot state, and logged data.

## Lab console commands

The second-terminal console attaches to the running lab process through a
same-UID Unix-domain socket. It exposes declarative observation and operator
commands only; it does **not** provide arbitrary Python or shell execution.

Useful commands include:

```text
status
    Show the lab PID, workspace, data directory, supervision state, and counts.

targets
    List all targets and current FunctionSlot/variant state.

state TARGET
    Show one target's FunctionSlot, behavior substitution, and code mutation.

policy TARGET
    Show the Repair, Logging, Guard, retry, and candidate-Guard policy.

summary TARGET
    Show Guard's recent aggregated behavior summary.

events [TARGET] [LIMIT]
    Show recent raw Guard behavior events.

deviations TARGET [LIMIT]
    Show deviations from the accepted Guard baseline.

inspections TARGET [LIMIT]
    Show runtime/code inspections, especially useful after __code__ mutation.

decisions [LIMIT]
    Show recent Guard decisions.

repair [TARGET] [LIMIT]
    Show recent Repair events.

approvals
    Show Repair episodes awaiting operator approval.

baseline TARGET
    Accept the current Guard baseline for a target.

approve EPISODE_ID
reject EPISODE_ID [REASON]
    Act on a pending Repair episode.

logs [LIMIT]
    Show recent persisted Caretaker application log records.

collector [LIMIT]
    Show events received by the synthetic loopback collector.
```

A target can be specified by menu number, short name, or target ID:

```text
1
divide
lab.divide
```

The console also supports one-shot commands. For example:

```bash
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab_console \
  events lab.divide 20
```

## Guard behavioral-drift experiment

To explore behavioral drift separately from bad input:

1. In Terminal 1, run a target using its **benign** implementation.
2. In Terminal 2, accept its baseline:

   ```text
   baseline lab.load_webpage
   ```

3. In Terminal 1, open **Modify implementations**.
4. Change the same target's behavior substitution to **malicious**.
5. Run the target again.
6. In Terminal 2, compare:

   ```text
   summary lab.load_webpage
   events lab.load_webpage
   deviations lab.load_webpage
   decisions
   collector
   ```

7. Restore the target in Terminal 1 when finished.

The contained `malicious` variants may perform unrelated filesystem,
subprocess, and loopback-network activity so Guard has something obvious to
observe. They are intentionally constrained to the laboratory workspace and
loopback interfaces.

## Runtime tampering experiment

Behavior substitution changes what the stable dispatcher calls. It does not
itself modify the active Caretaker FunctionSlot implementation.

To simulate an unauthorized runtime code change instead:

1. Run a target normally.
2. Open **Modify implementations**.
3. Select **Mutate the active dispatcher's `__code__` object**.
4. Choose a target and alternate implementation.
5. Run the target again.
6. From the lab console, examine:

   ```text
   state lab.divide
   inspections lab.divide
   events lab.divide
   decisions
   ```

This experiment shows the difference between a change in application behavior
and direct mutation of a Python code object.

The modification menu also provides **direct FunctionSlot injection**. This is
an intentionally out-of-band operation that bypasses the normal Repair provider
and validation pipeline so you can examine Caretaker's runtime state after an
unexpected implementation replacement.

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

## Running under the Caretaker supervisor

The lab console works whether the example is launched directly or under the
Caretaker supervisor. For experiments involving the standard Caretaker control
socket, start the application with:

```bash
PYTHONPATH=src:. python -m caretaker.run \
  --data-directory ./caretaker-interactive-lab/caretaker-data \
  examples.interactive_caretaker_lab
```

Then attach the lab console exactly as before:

```bash
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab_console
```

The supervisor's standard control socket is separate from the lab console. It
can be queried from another terminal with commands such as:

```bash
caretaker-logging control \
  ./caretaker-interactive-lab/caretaker-data/run/control.sock \
  status

caretaker-logging control \
  ./caretaker-interactive-lab/caretaker-data/run/control.sock \
  health

caretaker-logging control \
  ./caretaker-interactive-lab/caretaker-data/run/control.sock \
  policy-effective
```

The distinction is intentional:

- the **standard Caretaker control socket** reports supervisor/logging control
  state;
- the **example-specific lab console** exposes the live Guard and Repair objects
  created by this demonstration.

The lab console uses Caretaker's same-UID Unix-socket control mechanism, but its
commands are specific to this example and should not be mistaken for a general
production administration API.

## Custom data directory or lab root

By default, everything created by the example is placed below:

```text
./caretaker-interactive-lab/
```

Important paths are:

```text
caretaker-interactive-lab/
├── caretaker-data/
│   ├── application/        Caretaker log segments
│   └── run/
│       ├── control.sock    Standard supervisor socket, when supervised
│       └── lab-console.sock Example-specific observation console
└── workspace/              Synthetic files used by experiments
```

You can place the lab somewhere else by setting `CARETAKER_LAB_ROOT` in **both
terminals**:

```bash
CARETAKER_LAB_ROOT=/tmp/my-caretaker-lab \
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab
```

and:

```bash
CARETAKER_LAB_ROOT=/tmp/my-caretaker-lab \
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab_console
```

If the Caretaker data directory is otherwise customized, pass the socket path
explicitly:

```bash
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab_console \
  --socket /path/to/caretaker-data/run/lab-console.sock
```

## Safety notes

The built-in suspicious implementations are designed for observation, not for
damage. They are limited to laboratory-owned files, a fixed harmless child
process, and loopback HTTP traffic. The synthetic collector receives a digest,
not arbitrary user file contents.

However, some application menu options allow *you* to enter paths and URLs. If
you enter a real directory or an external URL, the application will attempt to
operate on what you supplied, subject to the target's own checks. For a clean
demonstration, use the default workspace and loopback endpoints first.

The example also exposes deliberate runtime mutation controls. Run it only in a
development/test environment.

## A useful testing rhythm

For most experiments, use this sequence:

```text
Terminal 1: run benign target
Terminal 2: inspect and optionally accept Guard baseline
Terminal 1: make one implementation or input change
Terminal 1: run again
Terminal 2: inspect Guard / Repair / logs
Terminal 2: approve or reject Repair if applicable
Terminal 1: restore target
Repeat with the next experiment
```

Changing only one thing at a time makes Caretaker's response much easier to
understand.
