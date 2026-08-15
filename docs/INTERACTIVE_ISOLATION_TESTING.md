# Interactive Isolation Testing for Caretaker 0.6.0a1

**Applies to:** Caretaker `0.6.0a1`
**Environment:** Multipass instance named `caretaker-lab`
**Purpose:** inspect Caretaker interactively inside an isolated environment, first as an installed Python package and then as an initialized supervised runtime.

## 1. Scope

This guide describes how to:

- enter the Multipass instance;
- run Python using the Caretaker virtual environment;
- inspect the installed package, modules, classes, methods, policies, and enums;
- review package metadata and installed files;
- inspect the effective Caretaker policy;
- start a test application under `caretaker.run`;
- open an interactive Python console after the Caretaker runtime has initialized;
- distinguish static package inspection from live runtime inspection.

This guide assumes the isolation layout used by the Caretaker `0.6.0a1` Multipass setup:

```text
Instance:             caretaker-lab
Caretaker virtualenv: /opt/caretaker/venv
Caretaker policy:     /etc/caretaker/application.toml
Runtime account:      caretaker-subject
Writable state:       /var/lib/caretaker
```

Adjust the paths when your installation differs.

## 2. Important distinction

There are two different forms of interactive inspection.

### Package inspection

This starts a normal Python interpreter and imports `caretaker`.

It allows inspection of:

- public exports;
- modules;
- classes;
- functions;
- policy objects;
- enums;
- source code included in the wheel;
- package metadata.

It does not necessarily initialize:

- the application supervisor;
- the Logging writer;
- Guard collectors;
- system collectors;
- the control socket;
- policy generations;
- administrative mode leases;
- Repair workers;
- the application under observation.

### Runtime inspection

This starts an application through Caretaker's supervised startup path and opens an interactive console from inside that application.

This allows inspection after the runtime has initialized:

- effective policy;
- Logging state;
- Guard state;
- supervisor state;
- worker state;
- runtime evidence configuration;
- application integration;
- initialized Caretaker objects exposed by the test application.

Package inspection is the safest place to begin. Runtime inspection provides deeper visibility but executes inside the supervised application process.

## 3. Enter the Multipass instance

From the host:

```bash
multipass shell caretaker-lab
```

Confirm the instance and current account:

```bash
hostname
id
```

The interactive Multipass shell usually runs as the default `ubuntu` account.

## 4. Start Python as the Caretaker runtime account

Use the same unprivileged account that normally runs the application:

```bash
sudo -u caretaker-subject \
  env HOME=/var/lib/caretaker \
  /opt/caretaker/venv/bin/python
```

This starts Python with:

- the installed Caretaker virtual environment;
- the same operating-system identity used by the subject application;
- the expected writable home and state directory;
- no root privileges.

Avoid using root for ordinary inspection. Running as root can hide permission problems and does not represent the normal Caretaker execution environment.

## 5. Basic package inspection

Inside Python:

```python
import caretaker

print(caretaker)
print(caretaker.__file__)
print(caretaker.__package__)
```

List public root exports:

```python
for name in sorted(dir(caretaker)):
    if not name.startswith("_"):
        print(name)
```

Open interactive help:

```python
help(caretaker)
```

Exit help with `q`.

## 6. Check the installed version

```python
from importlib.metadata import version

print(version("caretaker"))
```

To inspect additional package metadata:

```python
from importlib.metadata import metadata

info = metadata("caretaker")

for key in (
    "Name",
    "Version",
    "Summary",
    "Author",
    "License",
    "Requires-Python",
):
    print(f"{key}: {info.get(key)}")
```

List declared dependencies:

```python
requirements = info.get_all("Requires-Dist") or []

for requirement in requirements:
    print(requirement)
```

## 7. List Caretaker submodules

```python
import pkgutil
import caretaker

for module in pkgutil.walk_packages(
    caretaker.__path__,
    prefix="caretaker.",
):
    print(module.name)
```

To collect the names for later filtering:

```python
modules = sorted(
    module.name
    for module in pkgutil.walk_packages(
        caretaker.__path__,
        prefix="caretaker.",
    )
)

print(f"Discovered {len(modules)} modules")
```

Search for a particular subsystem:

```python
for name in modules:
    if "guard" in name:
        print(name)
```

Other useful search terms include:

```text
logging
repair
integrity
policy
provider
storage
supervisor
interrogation
```

## 8. Inspect classes and functions

Use Python's `inspect` module:

```python
import inspect
```

For a public class:

```python
from caretaker import RepairPolicy

print(inspect.signature(RepairPolicy))
print(inspect.getsource(RepairPolicy))
help(RepairPolicy)
```

For a method:

```python
print(inspect.signature(RepairPolicy.validate))
print(inspect.getsource(RepairPolicy.validate))
```

For a module:

```python
import caretaker.policy as policy

print(policy.__file__)
print(dir(policy))
print(inspect.getsource(policy))
```

For a specific function:

```python
print(inspect.signature(policy.load_policy))
print(inspect.getsource(policy.load_policy))
```

Replace `load_policy` with a function that actually exists in the installed version.

`inspect.getsource()` can fail for:

- native extensions;
- generated functions;
- objects without source files;
- implementation details provided by Python itself.

Caretaker's pure-Python modules should normally remain inspectable when the wheel includes their `.py` files.

## 9. Inspect dataclasses and policy fields

Many Caretaker policies and records are dataclasses.

```python
from dataclasses import fields, is_dataclass
from caretaker import RepairPolicy

print(is_dataclass(RepairPolicy))

for item in fields(RepairPolicy):
    print(
        item.name,
        item.type,
        item.default,
        item.default_factory,
    )
```

A cleaner helper:

```python
from dataclasses import MISSING, fields


def describe_dataclass(cls: type) -> None:
    for item in fields(cls):
        if item.default is not MISSING:
            default = item.default
        elif item.default_factory is not MISSING:
            default = "<factory>"
        else:
            default = "<required>"

        print(
            f"{item.name}: "
            f"type={item.type!r}, "
            f"default={default!r}"
        )
```

Use it with:

```python
describe_dataclass(RepairPolicy)
```

## 10. Inspect enums and selectable values

```python
from enum import Enum
import inspect
import caretaker


def show_enum(enum_cls: type[Enum]) -> None:
    print(enum_cls.__name__)

    for member in enum_cls:
        print(f"  {member.name} = {member.value!r}")
```

For a known enum:

```python
from caretaker import RepairAuthority

show_enum(RepairAuthority)
```

To discover root-level enums:

```python
for name in sorted(dir(caretaker)):
    value = getattr(caretaker, name)

    if inspect.isclass(value) and issubclass(value, Enum):
        print(name)
```

## 11. Inspect package metadata outside Python

Exit Python:

```python
exit()
```

Display package information:

```bash
/opt/caretaker/venv/bin/python -m pip show caretaker
```

List all installed package files:

```bash
/opt/caretaker/venv/bin/python -m pip show -f caretaker
```

Locate the package:

```bash
/opt/caretaker/venv/bin/python -c \
  'import caretaker; print(caretaker.__file__)'
```

List the installed package tree:

```bash
package_dir="$(
  /opt/caretaker/venv/bin/python -c \
  'import pathlib, caretaker; print(pathlib.Path(caretaker.__file__).parent)'
)"

find "$package_dir" -maxdepth 3 -type f | sort
```

## 12. Use pydoc

Display package documentation:

```bash
/opt/caretaker/venv/bin/python -m pydoc caretaker
```

Inspect a subsystem:

```bash
/opt/caretaker/venv/bin/python -m pydoc caretaker.guard
```

Inspect another module:

```bash
/opt/caretaker/venv/bin/python -m pydoc caretaker.logging
```

A local documentation server can also be started:

```bash
/opt/caretaker/venv/bin/python -m pydoc -p 8080
```

The text-based form is usually preferable in an isolated VM because it does not require opening a network port.

## 13. Activate the virtual environment

The default Multipass user can activate the virtual environment:

```bash
source /opt/caretaker/venv/bin/activate
```

Then:

```bash
python
```

This is convenient for static inspection, but it runs Python as the default Multipass user, not as `caretaker-subject`.

For permission-sensitive testing, continue to use:

```bash
sudo -u caretaker-subject \
  env HOME=/var/lib/caretaker \
  /opt/caretaker/venv/bin/python
```

## 14. Inspect the configured policy

Review the configured policy file:

```bash
sudo sed -n '1,240p' \
  /etc/caretaker/application.toml
```

Use Caretaker's policy commands when available:

```bash
sudo -u caretaker-subject \
  /opt/caretaker/venv/bin/caretaker-logging \
  policy explain \
  --file /etc/caretaker/application.toml
```

Review the effective policy:

```bash
sudo -u caretaker-subject \
  /opt/caretaker/venv/bin/caretaker-logging \
  policy effective \
  --file /etc/caretaker/application.toml
```

The exact command names depend on the installed `0.6.0a1` implementation. Confirm the available commands with:

```bash
/opt/caretaker/venv/bin/caretaker-logging --help
```

And:

```bash
/opt/caretaker/venv/bin/caretaker-logging policy --help
```

## 15. Inspect available Caretaker command-line interfaces

List scripts installed by the wheel:

```bash
ls -1 /opt/caretaker/venv/bin \
  | grep '^caretaker'
```

Ask each command for help:

```bash
/opt/caretaker/venv/bin/caretaker --help
```

```bash
/opt/caretaker/venv/bin/caretaker-logging --help
```

```bash
/opt/caretaker/venv/bin/caretaker-guard --help
```

```bash
/opt/caretaker/venv/bin/caretaker-integrity --help
```

Not every command is necessarily present under these exact names. Use the installed script listing as the source of truth.

## 16. Inspect the installed entry points

Inside Python:

```python
from importlib.metadata import entry_points

for item in entry_points(group="console_scripts"):
    if item.name.startswith("caretaker"):
        print(f"{item.name} -> {item.value}")
```

This reveals which function each Caretaker command invokes.

## 17. Importing Caretaker does not initialize the runtime

This:

```python
import caretaker
```

loads the package but does not automatically start the supervised application environment.

Static import alone does not prove that the following are active:

- Logging writer;
- Guard collectors;
- system collectors;
- control socket;
- policy generations;
- mode leases;
- Repair workers;
- supervised application process.

Use the normal Caretaker startup path to examine an initialized runtime.

## 18. Start the existing application under Caretaker

If an application is already installed and configured:

```bash
sudo -u caretaker-subject \
  env \
    HOME=/var/lib/caretaker \
    PYTHONUNBUFFERED=1 \
  /opt/caretaker/venv/bin/python \
  -m caretaker.run \
  --policy /etc/caretaker/application.toml \
  example_application
```

Replace `example_application` with the installed application module.

Use the exact startup command already proven to work in your environment when it differs from this example.

## 19. Create an interactive laboratory application

For deeper runtime inspection, create a small module that opens an interactive console after Caretaker initializes it.

Create:

```text
/opt/caretaker/app/caretaker_lab_app.py
```

with:

```python
from __future__ import annotations

import code
import os
import sys

import caretaker


def main() -> None:
    namespace = {
        "caretaker": caretaker,
        "os": os,
        "sys": sys,
    }

    code.interact(
        banner=(
            "Caretaker laboratory console\n"
            "The application is running under the Caretaker supervisor.\n"
            "Available names: caretaker, os, sys"
        ),
        local=namespace,
    )


if __name__ == "__main__":
    main()
```

The file should be installed or placed by the trusted administrator, not written by the `caretaker-subject` account.

Set ownership and permissions:

```bash
sudo chown root:root \
  /opt/caretaker/app/caretaker_lab_app.py

sudo chmod 0644 \
  /opt/caretaker/app/caretaker_lab_app.py
```

Confirm the subject cannot modify it:

```bash
sudo -u caretaker-subject \
  test ! -w /opt/caretaker/app/caretaker_lab_app.py
```

## 20. Launch the laboratory application

If `/opt/caretaker/app` is not already on `PYTHONPATH`:

```bash
sudo -u caretaker-subject \
  env \
    HOME=/var/lib/caretaker \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/caretaker/app \
  /opt/caretaker/venv/bin/python \
  -m caretaker.run \
  --policy /etc/caretaker/application.toml \
  caretaker_lab_app
```

If the module is installed into the virtual environment, omit `PYTHONPATH`.

Whether `caretaker.run` accepts an arbitrary standalone module in exactly this form depends on the installed `0.6.0a1` entry-point implementation. Use the same application-entry convention already used by your working Caretaker deployment.

## 21. Expand the interactive namespace carefully

The laboratory application can expose selected runtime objects.

For example:

```python
namespace = {
    "caretaker": caretaker,
    "os": os,
    "sys": sys,
    "application": application,
    "effective_policy": effective_policy,
    "supervisor": supervisor,
}
```

Only expose objects that are already available through supported application integration points.

Do not reach into arbitrary private attributes merely to obtain a console handle. That can create misleading conclusions about supported interfaces and can alter runtime behavior.

## 22. Inspect runtime state from the console

At the interactive prompt:

```python
caretaker.__file__
dir(caretaker)
```

Inspect known runtime objects exposed by the laboratory application:

```python
type(effective_policy)
dir(effective_policy)
```

```python
type(supervisor)
dir(supervisor)
```

Use `inspect` when appropriate:

```python
import inspect

print(inspect.signature(type(supervisor)))
print(inspect.getsource(type(supervisor)))
```

Avoid calling state-changing methods until their behavior, policy effect, and evidence consequences are understood.

## 23. Use a read-only inspection helper

A simple helper can reduce accidental changes:

```python
import inspect


def describe(obj: object) -> None:
    print(f"type: {type(obj)!r}")
    print(f"module: {type(obj).__module__}")
    print(f"qualified name: {type(obj).__qualname__}")

    for name in sorted(dir(obj)):
        if name.startswith("_"):
            continue

        try:
            value = getattr(obj, name)
        except Exception as exc:
            print(f"{name}: <error: {exc}>")
            continue

        if inspect.ismethod(value) or inspect.isfunction(value):
            try:
                signature = inspect.signature(value)
            except Exception:
                signature = "<unknown>"
            print(f"{name}{signature}")
        else:
            print(f"{name}: {value!r}")
```

Use:

```python
describe(effective_policy)
```

Do not use this helper on objects whose attribute access has side effects.

## 24. Inspect policy classes without changing runtime policy

It is safer to inspect policy declarations separately:

```python
from dataclasses import fields
from caretaker import RepairPolicy

for item in fields(RepairPolicy):
    print(item.name, item.type, item.default)
```

Inspect the effective policy through supported runtime or CLI interfaces rather than constructing replacement policy objects inside the application console.

## 25. Preserve evidence while inspecting

Interactive work can itself generate evidence.

Before beginning:

```bash
date -u
```

Record:

- VM name;
- Caretaker version;
- wheel hash;
- source revision;
- application version;
- policy hash;
- model and provider;
- active mode leases;
- current policy generation;
- reason for entering the interactive console.

Hash the policy:

```bash
sha256sum /etc/caretaker/application.toml
```

Record the installed wheel or distribution files when available:

```bash
/opt/caretaker/venv/bin/python -m pip show -f caretaker
```

When the original wheel remains available:

```bash
sha256sum /path/to/caretaker-0.6.0a1-py3-none-any.whl
```

## 26. Avoid modifying the installed package

Do not edit files under:

```text
/opt/caretaker/venv/lib/python*/site-packages/caretaker
```

Editing installed package files:

- invalidates the artifact being examined;
- can defeat Integrity checks;
- changes runtime behavior;
- makes results difficult to reproduce;
- can make the package disagree with its recorded version.

Use a new source revision and wheel for code changes.

## 27. Avoid using the console as a control bypass

The interactive console executes with the application account's privileges.

Do not use it to bypass:

- administrative mode leases;
- policy reload controls;
- Repair approval;
- baseline acceptance;
- Integrity precedence;
- evidence controls;
- supervisor lifecycle;
- declared runtime interfaces.

The purpose of the console is examination and controlled laboratory testing, not unrestricted administration.

## 28. Snapshot before runtime experiments

Before changing runtime behavior:

```bash
multipass stop caretaker-lab
```

Create a snapshot:

```bash
multipass snapshot caretaker-lab \
  --name before-interactive-runtime-test
```

Restart:

```bash
multipass start caretaker-lab
```

For repeatable experiments, restore the snapshot or create a fresh VM after each campaign.

## 29. Exit the interactive session

Exit Python:

```python
exit()
```

Or press:

```text
Ctrl-D
```

Exit the Multipass shell:

```bash
exit
```

When the laboratory application is running under the Caretaker supervisor, exit through the application console and allow the supervisor to perform its normal shutdown sequence.

Avoid terminating the VM abruptly unless testing crash recovery.

## 30. Recommended progression

### Stage 1: static package inspection

```bash
multipass shell caretaker-lab

sudo -u caretaker-subject \
  env HOME=/var/lib/caretaker \
  /opt/caretaker/venv/bin/python
```

Then:

```python
import caretaker
help(caretaker)
print(caretaker.__file__)
```

### Stage 2: declaration and policy inspection

Inspect:

- root exports;
- submodules;
- policy dataclasses;
- enums;
- function signatures;
- package metadata;
- installed command entry points.

### Stage 3: effective policy inspection

Use the policy CLI to review configured and effective behavior.

### Stage 4: supervised application startup

Run the existing test application through `caretaker.run`.

### Stage 5: interactive laboratory application

Open a console after the supervised runtime initializes.

### Stage 6: controlled experiments

Exercise:

- Logging;
- Guard;
- system collection;
- mode leases;
- interrogation;
- proposal-only Repair;
- approval-required Repair;
- probation;
- rollback;
- evidence verification.

Use a clean snapshot or fresh VM for each significant experiment.

## 31. Troubleshooting

### `ModuleNotFoundError: No module named 'caretaker'`

Confirm the virtual environment:

```bash
/opt/caretaker/venv/bin/python -m pip show caretaker
```

Confirm the interpreter:

```bash
/opt/caretaker/venv/bin/python -c \
  'import sys; print(sys.executable)'
```

### Permission denied reading the policy

Check:

```bash
ls -l /etc/caretaker/application.toml
id caretaker-subject
```

The policy can remain root-owned while still being readable by the intended subject group or account.

### Permission denied writing evidence

Check:

```bash
ls -ld /var/lib/caretaker
```

Test:

```bash
sudo -u caretaker-subject \
  test -w /var/lib/caretaker
```

### `inspect.getsource()` fails

Print:

```python
print(inspect.getfile(object_to_inspect))
```

Check whether the object is:

- native;
- generated;
- imported from another package;
- missing source files;
- wrapped by a decorator.

Try inspecting the module or unwrapped function:

```python
inspect.unwrap(object_to_inspect)
```

### `caretaker.run` does not accept the laboratory module

Check:

```bash
/opt/caretaker/venv/bin/python \
  -m caretaker.run \
  --help
```

Use the exact entry-point form supported by the installed release.

The project documentation available for this guide identifies supervised startup through `caretaker.run`, but it does not provide every implementation-specific argument form.

### Interactive input is not available

Confirm that the process has a terminal:

```bash
tty
```

Run the application directly from `multipass shell` rather than through a detached service.

### The console changes application behavior

An interactive console:

- keeps the main thread occupied;
- changes timing;
- may delay normal application work;
- can alter evidence volume;
- can affect timeout behavior.

Use it only in a dedicated laboratory application, not in a production workload.

## 32. Security interpretation

An interactive Python console is powerful. It has access to whatever the application account can access and whatever objects the laboratory application exposes.

The console does not provide a security boundary.

The boundary comes from:

- the disposable Multipass VM;
- the unprivileged subject account;
- root-owned Caretaker and policy files;
- restricted network access;
- absence of host mounts;
- external evidence and independent test oracles;
- destruction or restoration of the VM after testing.

Use the interactive console to understand Caretaker, inspect interfaces, and conduct controlled experiments. Do not treat it as a supported production administration interface unless a specific operation is exposed by Caretaker's declared control protocol.

## 33. Final checklist

Before inspection:

```text
[ ] Multipass instance is disposable or snapshotted
[ ] Caretaker version and wheel hash are recorded
[ ] application and policy identities are recorded
[ ] subject account is unprivileged
[ ] Caretaker and policy files are not writable by the subject
[ ] no host source directory is mounted
[ ] no production credentials are present
[ ] evidence location is writable
[ ] network restrictions are active
```

During inspection:

```text
[ ] static import is distinguished from runtime initialization
[ ] supported public interfaces are inspected first
[ ] private attributes are not modified casually
[ ] policy is not replaced from the console
[ ] interactive actions are recorded
[ ] application timing effects are considered
```

After inspection:

```text
[ ] console exited cleanly
[ ] supervisor completed normal shutdown
[ ] evidence exported when required
[ ] artifact and policy hashes retained
[ ] VM restored or destroyed
[ ] code changes made through a new source revision and wheel
```
