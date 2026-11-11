#!/bin/sh
# One-time setup of fat's release signing key (Ed25519), used by `fat update` to verify releases.
#
#   scripts/release-key.sh [PRIVATE-KEY-FILE]
#
# Writes the private key to PRIVATE-KEY-FILE (default: fat-release-signing.pem, mode 0600) and its
# public half to keys/release-signing.hex, which is built into fat. Then:
#   1. gh secret set FAT_RELEASE_SIGNING_KEY < fat-release-signing.pem
#   2. keep the .pem somewhere safe and offline (a password manager), and delete it here
#   3. commit keys/release-signing.hex
# Replacing the key later means releases signed with the new key are refused by fats built with
# the old one: they need one manual update.
set -eu
out=${1:-fat-release-signing.pem}
cd "$(dirname "$0")/.."
if [ -e "$out" ]; then
  echo "$out already exists; not overwriting it" >&2
  exit 1
fi
if grep -Eq '^[0-9a-f]{64}$' keys/release-signing.hex 2>/dev/null; then
  echo "keys/release-signing.hex already holds a key; empty it first if you mean to replace it" >&2
  exit 1
fi
umask 077
openssl genpkey -algorithm ed25519 -out "$out"
openssl pkey -in "$out" -pubout -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n' > keys/release-signing.hex
echo >> keys/release-signing.hex
echo "public key: $(cat keys/release-signing.hex) (keys/release-signing.hex)"
echo "private key: $out"
echo
echo "next:"
echo "  gh secret set FAT_RELEASE_SIGNING_KEY < $out"
echo "  store $out offline, then delete it here"
echo "  commit keys/release-signing.hex"
