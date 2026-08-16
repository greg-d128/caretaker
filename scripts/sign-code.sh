#!/bin/sh
set -eu

# Sign one reviewed canonical manifest. GnuPG owns all private-key operations.
if [ "$#" -ne 3 ]; then
    echo "usage: $0 MANIFEST FULL_FINGERPRINT OUTPUT.asc" >&2
    exit 2
fi

manifest=$1
fingerprint=$2
output=$3

test -f "$manifest" || { echo "manifest not found: $manifest" >&2; exit 2; }
test ! -e "$output" || { echo "refusing to overwrite: $output" >&2; exit 2; }
case "$fingerprint" in *[!0-9A-Fa-f]*|'')
    echo "signing key must be a full hexadecimal fingerprint" >&2
    exit 2
esac
test "${#fingerprint}" -ge 40 || {
    echo "signing key fingerprint is too short" >&2
    exit 2
}

sha256sum "$manifest"
gpg --local-user "$fingerprint" --armor --detach-sign --output "$output" "$manifest"
gpg --verify "$output" "$manifest"
echo "wrote verified detached signature: $output"
