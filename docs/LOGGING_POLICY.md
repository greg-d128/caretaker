# Logging policy

## Authority

The software administrator owns the effective deployment policy. Application code may emit records and recommend defaults but cannot accept baselines, approve overrides, select arbitrary policy files, or disable operator-required channels.

The policy snapshot records its source path, canonical hash, owner, permissions, and loaded time. The hash is attribution evidence, not a Caretaker authorization signature.

## Reconciliation

Application mode follows the base policy. Higher modes declare required capabilities. Missing capabilities produce explicit `LoggingPolicyOverride` records or prevent activation according to `PolicyConflictAction`.

```text
APPLY_REQUIRED_OVERRIDES
REFUSE_HIGHER_MODE
FALL_BACK_TO_APPLICATION_LOGGING
REQUIRE_INTERACTIVE_APPROVAL
```

## Mode leases

Temporary escalation is represented by `ModeLease`. A lease records scope, requester, reason, expiration, work identity, policy generation, and required overrides. Releasing it re-runs reconciliation against the current base policy rather than restoring a stale policy snapshot.

## Hot reload

The complete TOML document is parsed before replacement. On failure, the previous policy remains active. Safe runtime settings are applied immediately. Directory, codec, index layout, queue capacity, and runtime signing identity are startup- or run-bound and are reported as requiring a new supervised run.

## Security warnings

Caretaker warns when the application account owns the policy, the file is group/world writable, its directory is unsafe, or the path is a symbolic link. These warnings rely on operating-system permissions, not OpenPGP.

## Repair changes during evaluation

Every repair episode captures the effective logging-policy generation. A change before activation makes the pending repair `STALE_POLICY`; the candidate must be reviewed and revalidated before deployment.

## Worker health and restart

The supervised runtime maintains heartbeats for its writer, event server, control server, and optional system collector. In 0.6.1 the system collector is automatically restartable; writer and socket failures are detected and surfaced as degraded or failed health because safe reconnection and open-segment recovery must take precedence over blind restart.

Restart exhaustion may continue degraded, disable the affected component, or stop the supervised application. Caretaker workers do not elect a replacement supervisor; they remain subordinate to the application-scoped supervisor.


## Storage-unavailable default

Ordinary application logging now fails by stopping Caretaker logging rather than terminating the application. Deployments that require fail-closed audit semantics can explicitly set `storage_emergency.unavailable_action = STOP_APPLICATION`.


## Storage paths

Logging and system-collection output directories are normalized to absolute paths when policies are constructed. Relative paths loaded from a TOML policy are resolved relative to the policy file rather than the process working directory. This prevents a working-directory change from silently redirecting evidence storage.
