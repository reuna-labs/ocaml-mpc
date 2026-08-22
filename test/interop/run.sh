#!/bin/sh
# Cross-implementation validation against ZcashFoundation/frost.
#
# Needs a Rust toolchain and network access to fetch crates, which is why this is not
# part of `dune runtest`.
#
#   ./test/interop/run.sh
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
RUST="$HERE/rust"
MSG=${MSG:-"cross-implementation check"}
T=${T:-2}
N=${N:-3}

echo "building the Rust side (ZcashFoundation/frost)..."
( cd "$RUST" && cargo build --release --quiet )
THEIRS="$RUST/target/release/frost-interop"

echo "building the OCaml side..."
# Use the project's local switch: this script may be run from a shell that has not
# selected it, and a "dune: command not found" here is a confusing way to find that out.
if [ -d "$ROOT/_opam" ]; then
  eval "$(opam env --switch="$ROOT" --set-switch 2>/dev/null)"
fi
( cd "$ROOT" && dune build test/interop/interop.exe )
OURS="$ROOT/_build/default/test/interop/interop.exe"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

check_suite() {
  suite=$1
  echo
  echo "=== $suite ==="

  echo
  echo "1. their signature -> our verifier"
  "$THEIRS" "$suite:sign" "$T" "$N" "$MSG" > "$tmp/their_sig.json"
  "$OURS" "$suite" verify-theirs "$tmp/their_sig.json"

  echo
  echo "2. their key material -> our signing -> their verifier"
  "$THEIRS" "$suite:gen" "$T" "$N" "$MSG" > "$tmp/their_keys.json"
  "$OURS" "$suite" sign-with-theirs "$tmp/their_keys.json" "$T" > "$tmp/ours.txt"
  PK=$(sed -n 1p "$tmp/ours.txt")
  M=$(sed -n 2p "$tmp/ours.txt")
  SIG=$(sed -n 3p "$tmp/ours.txt")
  printf '  our signature, their verifier:            '
  "$THEIRS" "$suite:verify" "$PK" "$M" "$SIG"

  echo
  echo "3. their DKG round 1 -> our proof-of-knowledge verifier"
  "$THEIRS" "$suite:dkg1" "$T" "$N" > "$tmp/their_dkg1.json"
  "$OURS" "$suite" verify-their-dkg "$tmp/their_dkg1.json"
}

for suite in ${SUITES:-ed25519 secp256k1}; do
  check_suite "$suite"
done

echo
echo "all cross-implementation checks passed"
