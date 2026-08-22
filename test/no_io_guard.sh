#!/bin/sh
# Enforce the effect-layer boundary that lets ocaml-mpc cross-compile to a
# MirageOS/Solo5 unikernel:
#
#   core -- lib/mpc, lib/ed25519, lib/frost: no I/O at all, not Unix and not Lwt.
#   lwt  -- lib/lwt: Lwt is allowed, because MirageOS has no Eio backend and a
#           unikernel-capable transport therefore has to be Lwt-based. Unix is not:
#           the transport is functorised over Mirage_flow.S precisely so that it
#           does not need one.
#   unix -- lib/unix: the one package permitted to depend on Unix. Not checked.
#
# This inspects each library's declared dependencies rather than grepping the
# sources. That is the thing that actually enforces the boundary -- a library that
# does not declare a dependency cannot compile against it -- and unlike a grep it
# cannot be tripped by a module name appearing in prose.
set -eu

mode="$1"
shift

case "$mode" in
  core) banned='^(unix|lwt|lwt\.unix|async|threads(\.posix)?|mirage-flow-unix)$' ;;
  lwt)  banned='^(unix|lwt\.unix|async|threads(\.posix)?|mirage-flow-unix)$' ;;
  *) echo "usage: $0 core|lwt <dir>..." >&2; exit 2 ;;
esac

status=0
for root in "$@"; do
  for dune in $(find "$root" -name dune); do
    # Take the (libraries ...) stanza, drop comment lines, split into words.
    deps=$(sed -e 's/;.*$//' "$dune" \
      | tr '\n' ' ' \
      | sed -n 's/.*(libraries \([^)]*\)).*/\1/p' \
      | tr ' ' '\n' \
      | sed '/^$/d')
    for d in $deps; do
      if printf '%s\n' "$d" | grep -Eq "$banned"; then
        echo "no-I/O guard ($mode) failed: $dune declares a dependency on '$d'." >&2
        status=1
      fi
    done
  done
done

[ "$status" -eq 0 ] && echo "no-I/O guard passed ($mode: $*)"
exit "$status"
