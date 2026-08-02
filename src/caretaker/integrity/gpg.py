from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from random import Random

from .models import (
    RolePolicy,
    SignatureVerification,
    SignatureVerificationMode,
    ThresholdVerification,
    normalize_fingerprint,
)


_FATAL_STATUS = {
    "BADSIG",
    "ERRSIG",
    "EXPSIG",
    "EXPKEYSIG",
    "REVKEYSIG",
    "NO_PUBKEY",
    "KEYEXPIRED",
    "SIGEXPIRED",
}


class GPGUnavailableError(RuntimeError):
    pass


class GPGVerifier:
    """Verify detached OpenPGP signatures with public keys only.

    The verifier creates an isolated temporary GnuPG home, imports only the
    supplied public certificates, disables automatic key retrieval, and parses
    machine-readable status records. It contains no signing functionality.

    ``RANDOMIZED_RUNTIME`` is deliberately probabilistic. It selects identities
    from the signer set authenticated by the root metadata using a cryptographic
    random source. It still requires the expected number of detached signature
    files to be present, but cryptographically evaluates only the selected
    identities. Full publication verification remains available for release and
    forensic workflows.
    """

    def __init__(
        self,
        executable: str = "gpg",
        *,
        allowed_hash_algorithm_ids: tuple[int, ...] = (8, 9, 10, 11),
        random_source: Random | None = None,
    ) -> None:
        resolved = shutil.which(executable)
        if resolved is None:
            raise GPGUnavailableError(f"OpenPGP verifier {executable!r} was not found")
        self.executable = resolved
        self.allowed_hash_algorithm_ids = frozenset(allowed_hash_algorithm_ids)
        self._random = random_source or secrets.SystemRandom()

    def verify_threshold(
        self,
        *,
        signed_path: str | Path,
        signature_paths: Sequence[str | Path] | Mapping[str, str | Path],
        public_key_paths: Sequence[str | Path],
        role: RolePolicy,
        mode: SignatureVerificationMode = SignatureVerificationMode.AUTHORIZATION_THRESHOLD,
    ) -> ThresholdVerification:
        if mode is SignatureVerificationMode.RANDOMIZED_RUNTIME:
            return self.verify_randomized(
                signed_path=signed_path,
                signature_paths=signature_paths,
                public_key_paths=public_key_paths,
                role=role,
            )

        required = role.threshold_for(mode)
        signature_map, signature_list = _normalize_signature_paths(signature_paths)
        if not signature_list:
            return _empty_result(role, required, mode, "No detached signatures were supplied")

        with tempfile.TemporaryDirectory(prefix="caretaker-gpg-") as temporary:
            home = Path(temporary)
            os.chmod(home, 0o700)
            import_error = self._import_public_keys(home, public_key_paths)
            if import_error:
                return _empty_result(role, required, mode, import_error)

            results = tuple(
                self._verify_signature(home, Path(signature), Path(signed_path))
                for signature in signature_list
            )

        authorized = set(role.authorized_primary_fingerprints)
        mapped_expectations = {Path(path): fingerprint for fingerprint, path in signature_map.items()}
        valid_primary: list[str] = []
        errors: list[str] = []
        seen: set[str] = set()
        for result in results:
            if not result.valid or result.primary_fingerprint is None:
                errors.append(f"Invalid signature: {result.signature_path}: {result.error or 'verification failed'}")
                continue
            primary = normalize_fingerprint(result.primary_fingerprint)
            expected = mapped_expectations.get(Path(result.signature_path))
            if expected is not None and primary != expected:
                errors.append(
                    f"Signature mapping expected primary fingerprint {expected}, but {result.signature_path} "
                    f"was signed by {primary}"
                )
                continue
            if primary not in authorized:
                errors.append(f"Signature from unauthorized primary fingerprint {primary}")
                continue
            if primary in seen:
                errors.append(f"Duplicate signer does not increase threshold: {primary}")
                continue
            seen.add(primary)
            valid_primary.append(primary)

        satisfied = len(valid_primary) >= required
        if not satisfied:
            errors.append(
                f"Role {role.name!r} requires {required} distinct authorized signatures in "
                f"{mode.value} mode; found {len(valid_primary)}"
            )
        return ThresholdVerification(
            role_name=role.name,
            required_threshold=required,
            authorized_primary_fingerprints=role.authorized_primary_fingerprints,
            valid_primary_fingerprints=tuple(valid_primary),
            signature_results=results,
            satisfied=satisfied,
            errors=tuple(errors),
            verification_mode=mode,
            selected_primary_fingerprints=tuple(role.authorized_primary_fingerprints),
            expected_publication_signatures=role.publication_threshold,
        )

    def verify_randomized(
        self,
        *,
        signed_path: str | Path,
        signature_paths: Sequence[str | Path] | Mapping[str, str | Path],
        public_key_paths: Sequence[str | Path],
        role: RolePolicy,
    ) -> ThresholdVerification:
        sample_size = role.threshold_for(SignatureVerificationMode.RANDOMIZED_RUNTIME)
        publication_count = role.publication_threshold or len(role.authorized_primary_fingerprints)
        signature_map, signature_list = _normalize_signature_paths(signature_paths)
        supplied_count = len(signature_map) if signature_map else len(signature_list)
        if supplied_count < publication_count:
            return _empty_result(
                role,
                sample_size,
                SignatureVerificationMode.RANDOMIZED_RUNTIME,
                f"Randomized runtime verification expects {publication_count} detached signature files; "
                f"received {supplied_count}",
            )

        selected = tuple(
            self._random.sample(list(role.authorized_primary_fingerprints), sample_size)
        )
        if signature_map and set(signature_map) != set(role.authorized_primary_fingerprints):
            missing = sorted(set(role.authorized_primary_fingerprints) - set(signature_map))
            extra = sorted(set(signature_map) - set(role.authorized_primary_fingerprints))
            details = []
            if missing:
                details.append("missing " + ", ".join(missing))
            if extra:
                details.append("unauthorized " + ", ".join(extra))
            return _empty_result(
                role,
                sample_size,
                SignatureVerificationMode.RANDOMIZED_RUNTIME,
                "Fingerprint-to-signature mapping does not exactly cover the authorized set: "
                + "; ".join(details),
                selected=selected,
            )
        all_signatures = list(signature_list)
        self._random.shuffle(all_signatures)
        results: list[SignatureVerification] = []
        valid_primary: list[str] = []
        errors: list[str] = []
        used_paths: set[Path] = set()

        with tempfile.TemporaryDirectory(prefix="caretaker-gpg-") as temporary:
            home = Path(temporary)
            os.chmod(home, 0o700)
            import_error = self._import_public_keys(home, public_key_paths)
            if import_error:
                return _empty_result(
                    role,
                    sample_size,
                    SignatureVerificationMode.RANDOMIZED_RUNTIME,
                    import_error,
                    selected=selected,
                )

            for expected_primary in selected:
                matched = False
                if signature_map:
                    signature = Path(signature_map[expected_primary])
                    result = self._verify_signature(home, signature, Path(signed_path))
                    results.append(result)
                    if result.valid and result.primary_fingerprint is not None:
                        observed = normalize_fingerprint(result.primary_fingerprint)
                        if observed == expected_primary:
                            used_paths.add(signature)
                            valid_primary.append(observed)
                            matched = True
                    if not matched:
                        errors.append(
                            "Mapped detached signature did not validate for randomly selected primary "
                            f"fingerprint {expected_primary}"
                        )
                    continue
                candidates = [item for item in all_signatures if item not in used_paths]
                self._random.shuffle(candidates)
                for signature in candidates:
                    result = self._verify_signature(home, signature, Path(signed_path))
                    results.append(result)
                    if not result.valid or result.primary_fingerprint is None:
                        continue
                    observed = normalize_fingerprint(result.primary_fingerprint)
                    if observed == expected_primary:
                        used_paths.add(signature)
                        valid_primary.append(observed)
                        matched = True
                        break
                if not matched:
                    errors.append(
                        "No valid detached signature was found for randomly selected primary "
                        f"fingerprint {expected_primary}"
                    )

        satisfied = len(valid_primary) == sample_size and not errors
        return ThresholdVerification(
            role_name=role.name,
            required_threshold=sample_size,
            authorized_primary_fingerprints=role.authorized_primary_fingerprints,
            valid_primary_fingerprints=tuple(valid_primary),
            signature_results=tuple(results),
            satisfied=satisfied,
            errors=tuple(errors),
            verification_mode=SignatureVerificationMode.RANDOMIZED_RUNTIME,
            selected_primary_fingerprints=selected,
            expected_publication_signatures=publication_count,
        )

    def _import_public_keys(self, home: Path, public_key_paths: Sequence[str | Path]) -> str | None:
        if not public_key_paths:
            return "No independently acquired public-key files were supplied"
        for key_path in public_key_paths:
            inspection = subprocess.run(
                [
                    self.executable,
                    "--homedir",
                    str(home),
                    "--batch",
                    "--with-colons",
                    "--show-keys",
                    str(Path(key_path)),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if inspection.returncode != 0:
                return f"Could not inspect public-key file {key_path}: {inspection.stderr.strip()}"
            record_types = {line.split(":", 1)[0] for line in inspection.stdout.splitlines()}
            if "sec" in record_types or "ssb" in record_types:
                return f"Secret-key material is not accepted by the Caretaker verifier: {key_path}"
            if "pub" not in record_types:
                return f"No OpenPGP public certificate found in {key_path}"
        command = [
            self.executable,
            "--homedir",
            str(home),
            "--batch",
            "--no-auto-key-retrieve",
            "--import-options",
            "import-minimal,import-clean",
            "--import",
            *(str(Path(path)) for path in public_key_paths),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            return f"Public-key import failed: {completed.stderr.strip()}"
        return None

    def _verify_signature(self, home: Path, signature: Path, signed: Path) -> SignatureVerification:
        command = [
            self.executable,
            "--homedir",
            str(home),
            "--batch",
            "--no-auto-key-retrieve",
            "--no-auto-key-import",
            "--status-fd",
            "1",
            "--verify",
            str(signature),
            str(signed),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        status_records = _status_records(completed.stdout)
        status_codes = tuple(record[0] for record in status_records)
        valid_record = next((record for record in status_records if record[0] == "VALIDSIG"), None)
        fatal = sorted(set(status_codes) & _FATAL_STATUS)

        signing_fingerprint: str | None = None
        primary_fingerprint: str | None = None
        if valid_record is not None and len(valid_record) >= 2:
            signing_fingerprint = normalize_fingerprint(valid_record[1])
            if len(valid_record) >= 11 and _looks_like_fingerprint(valid_record[-1]):
                primary_fingerprint = normalize_fingerprint(valid_record[-1])
            else:
                primary_fingerprint = signing_fingerprint

        public_key_algorithm_id: int | None = None
        hash_algorithm_id: int | None = None
        signature_class: str | None = None
        if valid_record is not None and len(valid_record) >= 10:
            try:
                public_key_algorithm_id = int(valid_record[7])
                hash_algorithm_id = int(valid_record[8])
                signature_class = valid_record[9]
            except (TypeError, ValueError):
                fatal.append("MALFORMED_VALIDSIG")
        if hash_algorithm_id is not None and hash_algorithm_id not in self.allowed_hash_algorithm_ids:
            fatal.append(f"DISALLOWED_HASH_ALGORITHM_{hash_algorithm_id}")

        valid = completed.returncode == 0 and valid_record is not None and not fatal
        error = None
        if not valid:
            if fatal:
                error = "GnuPG status: " + ", ".join(fatal)
            elif completed.stderr.strip():
                error = completed.stderr.strip()
            else:
                error = "GnuPG did not emit a valid-signature record"

        return SignatureVerification(
            signature_path=str(signature),
            valid=valid,
            signing_fingerprint=signing_fingerprint,
            primary_fingerprint=primary_fingerprint,
            status_codes=status_codes,
            public_key_algorithm_id=public_key_algorithm_id,
            hash_algorithm_id=hash_algorithm_id,
            signature_class=signature_class,
            stderr=completed.stderr.strip(),
            error=error,
        )


def _normalize_signature_paths(
    signature_paths: Sequence[str | Path] | Mapping[str, str | Path],
) -> tuple[dict[str, Path], tuple[Path, ...]]:
    if isinstance(signature_paths, Mapping):
        mapped = {normalize_fingerprint(key): Path(value) for key, value in signature_paths.items()}
        if len(mapped) != len(signature_paths):
            raise ValueError("Duplicate normalized fingerprints in signature mapping")
        return mapped, tuple(mapped.values())
    return {}, tuple(Path(item) for item in signature_paths)


def _empty_result(
    role: RolePolicy,
    required: int,
    mode: SignatureVerificationMode,
    error: str,
    *,
    selected: tuple[str, ...] = (),
) -> ThresholdVerification:
    return ThresholdVerification(
        role_name=role.name,
        required_threshold=required,
        authorized_primary_fingerprints=role.authorized_primary_fingerprints,
        valid_primary_fingerprints=(),
        signature_results=(),
        satisfied=False,
        errors=(error,),
        verification_mode=mode,
        selected_primary_fingerprints=selected,
        expected_publication_signatures=role.publication_threshold,
    )


def _status_records(output: str) -> list[list[str]]:
    records: list[list[str]] = []
    prefix = "[GNUPG:] "
    for line in output.splitlines():
        if line.startswith(prefix):
            fields = line[len(prefix):].split()
            if fields:
                records.append(fields)
    return records


def _looks_like_fingerprint(value: str) -> bool:
    compact = value.strip().upper()
    return len(compact) >= 40 and all(character in "0123456789ABCDEF" for character in compact)
