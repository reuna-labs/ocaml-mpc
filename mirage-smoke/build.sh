#!/bin/sh
# Build, and optionally boot, the ocaml-mpc smoke unikernel against the local
# Mirage, Solo5 and mirage-crypto working trees.
#
# Modelled on enclave-samples/*/ocaml-mirage/build.sh, which is the recipe this
# repository already uses for OCaml unikernels.
#
#   TARGET=spt|hvt|sptmac|virtio|muen|nitro|sgx|cca|snp|tdx   (default spt)
#   PLATFORM=linux/arm64|linux/amd64
#   C=container-name
#   RUN=1|0   -- spt and nitro boot inside an ordinary Linux container
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
MPC=$(cd "$HERE/.." && pwd)
REUNA=$(cd "$MPC/.." && pwd)
IMG=${IMG:-ocaml/opam:debian-12-ocaml-5.2}
TARGET=${TARGET:-spt}
PLATFORM=${PLATFORM:-linux/arm64}
C=${C:-ocaml-mpc-smoke}
RUN=${RUN:-1}

if ! docker ps -a --format '{{.Names}}' | grep -qx "$C"; then
  docker run -d --name "$C" --platform "$PLATFORM" \
    -v "$REUNA":/reuna -w /reuna/ocaml-mpc "$IMG" sleep infinity >/dev/null
fi
docker start "$C" >/dev/null 2>&1 || true

docker exec "$C" bash -lc '
  set -e
  eval $(opam env)
  sudo apt-get update -qq
  sudo apt-get install -y -qq pkg-config m4 libgmp-dev libseccomp-dev rsync \
    binutils-aarch64-linux-gnu >/dev/null

  mkdir -p /tmp/reuna-mirage /tmp/reuna-mirage-crypto
  rsync -a --delete --exclude=.git --exclude=_build --exclude=_opam \
    /reuna/mirage/ /tmp/reuna-mirage/
  rsync -a --delete --exclude=.git --exclude=_build --exclude=_opam \
    /reuna/ocaml/mirage-crypto/ /tmp/reuna-mirage-crypto/

  if ! test -x /tmp/reuna-solo5/configure.sh; then
    mkdir -p /tmp/reuna-solo5
    git -C /reuna/solo5 archive HEAD | tar -x -C /tmp/reuna-solo5
  fi
  cp /reuna/solo5/include/version.h /tmp/reuna-solo5/include/version.h.distrib
  if ! test -x /tmp/reuna-ocaml-solo5-1.0.1/configure.sh; then
    opam source ocaml-solo5.1.0.1 --dir /tmp/reuna-ocaml-solo5-1.0.1
  fi

  opam pin add -yn mirage.4.11.1 /tmp/reuna-mirage
  opam pin add -yn mirage-runtime.4.11.1 /tmp/reuna-mirage
  opam pin add -yn solo5.0.12.0 /tmp/reuna-solo5
  opam pin add -yn ocaml-solo5.1.0.1 /tmp/reuna-ocaml-solo5-1.0.1

  # The whole mirage-crypto family must come from ONE source. The fork has diverged
  # from the released packages -- an upstream mirage-crypto-rng-mirage against the
  # forked mirage-crypto-rng fails to build with "Unbound value entropy_test" -- so
  # rng-mirage is pinned here too, not just the three packages ocaml-mpc itself needs.
  for package in mirage-crypto mirage-crypto-rng mirage-crypto-rng-mirage \
      mirage-crypto-ec; do
    opam pin add -yn "$package.2.4.0" /tmp/reuna-mirage-crypto
  done

  # rsync rather than pinning /reuna/ocaml-mpc directly: it is not a git repository,
  # so opam would copy the whole directory including _opam and _build.
  mkdir -p /tmp/reuna-ocaml-mpc
  rsync -a --delete --exclude=.git --exclude=_build --exclude=_opam \
    /reuna/ocaml-mpc/ /tmp/reuna-ocaml-mpc/
  opam pin add -yn mpc.dev /tmp/reuna-ocaml-mpc
  opam pin add -yn mpc-lwt.dev /tmp/reuna-ocaml-mpc

  opam install -y mirage mirage-runtime solo5 ocaml-solo5 \
    mirage-crypto-rng-mirage mpc mpc-lwt
'

docker exec "$C" bash -lc "
  set -e
  eval \$(opam env)
  cd /reuna/ocaml-mpc/mirage-smoke
  if test '$TARGET' = sptmac; then
    cp /reuna/solo5/bindings/solo5_sptmac.o \
      /reuna/solo5/bindings/solo5_sptmac.lds \
      \"\$(opam var prefix)/lib/aarch64-solo5-none-static/\"
  fi
  mirage clean >/dev/null 2>&1 || true
  mirage configure -t '$TARGET'
  # ocaml-solo5 does not provide fstat; the generated manifest links against it.
  printf 'int fstat(int fd, void *buf){(void)fd;(void)buf;return -1;}\\n' \
    > fstat_stub.c
  sed -i 's/(names manifest)/(names manifest fstat_stub)/' dune.build
  # Re-vendor when the local sources have changed. Skipping this whenever duniverse/
  # merely exists silently reuses a stale copy of ocaml-mpc: that is how adding the
  # secp256k1 library produced a not-found error from a tree that plainly contained it.
  stamp=duniverse/.ocaml-mpc.stamp
  current=\$(find /tmp/reuna-ocaml-mpc/lib /tmp/reuna-ocaml-mpc/dune-project \
    /tmp/reuna-ocaml-mpc/mirage-smoke -type f 2>/dev/null \
    | sort | xargs sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1)
  if ! test -d duniverse || ! test -f \$stamp \
     || test \"\$(cat \$stamp)\" != \"\$current\"; then
    rm -rf duniverse
    make depends
    mkdir -p duniverse && printf '%s' \"\$current\" > \$stamp
  fi
  if test '$TARGET' = cca; then
    SOLO5_READELF=aarch64-linux-gnu-readelf \
    SOLO5_OBJCOPY=aarch64-linux-gnu-objcopy make build
  else
    make build
  fi
  if test '$RUN' = 1; then
    case '$TARGET' in
      spt|nitro) solo5-'$TARGET' dist/mpc_smoke.'$TARGET' ;;
      *) echo 'RUN=1 ignored: no container-safe tender for $TARGET' ;;
    esac
  fi
"
