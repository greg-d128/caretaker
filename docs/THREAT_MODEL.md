# Integrity threat model

The integrity subsystem provides release provenance, tamper evidence, and an experimental population-level verification mechanism. It is not complete containment of a privileged attacker.

## Intended guarantees

Starting from independently authenticated primary fingerprints or a previously accepted root, Caretaker can establish that:

- canonical metadata was authorized by the required OpenPGP primary identities;
- full publication verification validates all three expected signatures;
- randomized runtime verification selected identities from the authenticated root using a cryptographic random source;
- protected and root runtime sampling never weakens the 2-of-3 authorization threshold;
- source and release artifacts match signed byte lengths and SHA-256 hashes;
- root transitions are sequential and satisfy both old and new root thresholds;
- lower root or manifest versions can be rejected using retained state;
- runtime function code can be compared with locally accepted fingerprints;
- integrity evidence remains separate from ordinary repair incidents.

## Non-guarantees

Signatures and sampling do not prove that:

- authorized code is safe or correct;
- a signing environment was uncompromised;
- the initial local public keys are authentic without an external trust path;
- the presented release is the newest release without retained state or another freshness source;
- unselected signatures were valid during a randomized verification;
- random selections remain unpredictable after the verifier or operating system is compromised;
- a privileged attacker cannot replace the interpreter, verifier, public keys, random source, and trusted state together;
- generated in-memory code is release-authorized.

## All-three publication policy

All published manifests are expected to carry signatures from keys A, B, and C. Full verification checks all three. The authorization thresholds remain 1-of-3 for ordinary release code and 2-of-3 for protected/root policy so continuity and emergency operations remain possible.

A publication signed by all three identities makes missing or changed signature records externally visible. It does not prevent an attacker who controls enough private keys from producing a cryptographically valid malicious publication.

## Probabilistic runtime verification

Ordinary runtime checks select one of the three identities. Protected and root runtime checks select two distinct identities.

For ordinary code, a forged manifest signed with one compromised key passes one independent runtime check with probability 1/3. With two compromised keys, it passes with probability 2/3. For protected code, one compromised key is insufficient; two compromised keys pass only when that exact pair is selected, with probability 1/3.

This improves the chance that a partially compromised signing set is detected somewhere across a broad population. It deliberately accepts lower assurance for any single ordinary-code process than full 3-of-3 verification. Full verification remains the correct mode for installation, release acceptance, CI, and investigation.

Repeated checks within one process are useful only if their selections are independent and the attacker cannot observe or influence the random source before presenting the forged inputs.

## Key compromise and independence

Three keys provide threshold value only when they are not all exposed through one common failure domain. Separate vault credentials, signing sessions, devices, and backups improve independence.

- One compromised key can create an ordinary signature and may pass a sampled ordinary check.
- One compromised key cannot satisfy protected/root randomized sampling or 2-of-3 authorization.
- Two compromised keys can satisfy the protected/root authorization threshold and pass a protected randomized check with probability 1/3.
- Three compromised keys defeat the signing model until externally detected and replaced.

The project owner’s independent signature records and published fingerprints provide an audit trail, but do not automatically prevent a coordinated compromise.

## Scheduled rotation

Root schema V2 records a rolling schedule in which one slot is rotated every two years and the complete A/B/C set cycles approximately every six years. The schedule is intended to reduce long-lived key exposure and make unexpected key changes easier to notice.

Rotation warnings are advisory. Cryptographic trust still depends on valid sequential root transitions. A compromised environment may suppress warnings, and a fixed schedule cannot prove that a private key was never copied.

## Root rotation

The 2-of-3 root policy allows one primary certificate to be replaced while two unaffected identities preserve continuity. A new root must satisfy both the old and new root policies. Signing-subkey replacement under the same primary certificate does not change threshold identity.

## Runtime self-verification limitation

A Python package cannot establish absolute trust by asking already-running Python code to inspect itself. Runtime verification detects ordinary disk and memory modification, but a final security boundary may require interpreter, operating-system, kernel, secure-boot, or hardware support.

## Relationship to self-repair

Integrity failures are not ordinary application defects. Caretaker should not automatically rewrite sealed verification logic or suspicious third-party code. Default responses are evidence capture, refusal to import or activate, disabling repair, or terminating startup according to integrity class.

## Manifest coverage

Manifests sign coverage and exclusion patterns in addition to individual files. Verification rejects matching files omitted from the artifact list and separately enforces root-protected and sealed path classifications.

This detects many added-file attacks inside the declared tree. It does not detect code loaded from outside that tree, a compromised Python installation, or a malicious operating-system loader.

## Guard threat model

Guard extends Caretaker from release integrity into runtime evidence. It can detect significant observable deviations such as new destinations, filesystem roots, subprocesses, imports, dynamic code, rate changes, and runtime Python code replacement.

It does not guarantee complete observation of hostile code. Native extensions, `ctypes`, subprocesses, a compromised interpreter, or a privileged operating-system attacker may bypass or alter Python-level monitoring.

Behavior baselines are versioned and require explicit acceptance to reduce gradual poisoning. LLM assessments remain advisory and cannot override integrity failures, sealed-code restrictions, explicit deny policies, failed functional validation, or failed regression cases.

Module routing is reliable before import. Quarantine of an already loaded dependency normally requires a clean supervised restart because existing references cannot be rewritten safely in general.
