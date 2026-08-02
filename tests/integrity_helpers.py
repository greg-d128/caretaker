from __future__ import annotations

import os
import subprocess
from pathlib import Path


def make_gpg_home(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def generate_test_key(home: Path, identity: str, *, signing_subkey: bool = False) -> str:
    usage = "cert" if signing_subkey else "sign"
    _run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            identity,
            "ed25519",
            usage,
            "0",
        ]
    )
    fingerprint = _primary_fingerprint(home, identity)
    if signing_subkey:
        _run(
            [
                "gpg",
                "--homedir",
                str(home),
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-add-key",
                fingerprint,
                "ed25519",
                "sign",
                "0",
            ]
        )
    return fingerprint


def export_public_key(home: Path, fingerprint: str, output: Path) -> None:
    completed = _run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--armor",
            "--export",
            fingerprint,
        ],
        text=False,
    )
    output.write_bytes(completed.stdout)


def export_secret_key(home: Path, fingerprint: str, output: Path) -> None:
    completed = _run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--armor",
            "--export-secret-keys",
            fingerprint,
        ],
        text=False,
    )
    output.write_bytes(completed.stdout)


def sign_file(home: Path, fingerprint: str, source: Path, output: Path) -> None:
    _run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--local-user",
            fingerprint,
            "--armor",
            "--detach-sign",
            "--output",
            str(output),
            str(source),
        ]
    )


def _primary_fingerprint(home: Path, identity: str) -> str:
    completed = _run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--with-colons",
            "--fingerprint",
            identity,
        ]
    )
    for line in completed.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "fpr":
            return fields[9]
    raise RuntimeError("test key fingerprint not found")


def _run(command: list[str], *, text: bool = True) -> subprocess.CompletedProcess:
    completed = subprocess.run(command, capture_output=True, text=text, check=False)
    if completed.returncode != 0:
        stderr = completed.stderr if text else completed.stderr.decode(errors="replace")
        raise RuntimeError(f"Command failed: {' '.join(command)}\n{stderr}")
    return completed
