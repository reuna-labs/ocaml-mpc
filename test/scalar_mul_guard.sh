#!/bin/sh
# Element.scalar_mul is variable time in its scalar. FROST is safe with that only
# because it applies it exclusively to public values -- binding factors, participant
# identifiers, the challenge, Lagrange coefficients. That is a property of the call
# sites, not of the type system, so it is checked here: a new call site in a file that
# is not on the allowlist fails the build, and whoever adds one has to say why their
# scalar is public.
set -eu
root="${1:-lib}"
allow="${2:-scalar_mul_allowlist.txt}"

files=$(find "$root" -name '*.ml' \
  | xargs grep -l 'scalar_mul[^_]' 2>/dev/null \
  | while read -r f; do
      # A definition of scalar_mul is not a use of it.
      if grep -E '(El|C\.Element|Element)\.scalar_mul[^_]' "$f" >/dev/null 2>&1; then
        printf '%s\n' "$f"
      fi
    done)

status=0
for f in $files; do
  base=$(printf '%s\n' "$f" | sed 's|^.*/lib/|lib/|')
  if ! grep -q "^$base[[:space:]]" "$allow"; then
    echo "scalar_mul guard: $f uses Element.scalar_mul but is not on the allowlist." >&2
    echo "  Element.scalar_mul is NOT constant time. Add $base to $allow with the" >&2
    echo "  reason its scalar is public, or use scalar_mul_base." >&2
    status=1
  fi
done
[ "$status" -eq 0 ] && echo "scalar_mul guard passed ($(printf '%s' "$files" | wc -w | tr -d ' ') call sites, all allowlisted)"
exit "$status"
