# Solo5 smoke test

A compute-only MirageOS unikernel that proves two things about `ocaml-mpc`, and only
two:

1. **It links and runs under Solo5.** No `Unix`, no missing symbol, no C stub that
   exists only on a hosted platform.
2. **The arithmetic gives the same answers there.** The RFC 9591 Appendix E.1
   known-answer vector is checked in-kernel, followed by a full distributed key
   generation and threshold signing, with the result verified against
   `Mirage_crypto_ec.Ed25519.verify`. A cross-compilation that silently changed a
   result fails here rather than in production.

There is no network. Peers talk over an in-memory channel: the transport is covered by
the socket tests on the host, and adding a device stack here would broaden what can go
wrong without broadening what is proved.

## Running it

```sh
./build.sh                  # spt on linux/arm64, boots in the container
TARGET=hvt RUN=0 ./build.sh
```

The script follows the recipe the other OCaml unikernels in this repository use
(`enclave-samples/*/ocaml-mirage/build.sh`): a Debian container with the local
`mirage`, `solo5`, `ocaml-solo5` and `mirage-crypto` working trees pinned, then
`mirage configure` and `make depends` to vendor everything into `duniverse/`.

## The same checks, without the cross-build

`dune runtest` on the host runs the identical file — `test/smoke/` copies
`unikernel.ml` rather than duplicating it — so a type error or a broken check shows up
in seconds instead of after a container build.

## A pin that is easy to get wrong

The whole `mirage-crypto` family has to come from one source. The Reuna fork has
diverged from the released packages, and an upstream `mirage-crypto-rng-mirage` built
against the fork's `mirage-crypto-rng` fails with `Unbound value entropy_test`. So
`build.sh` pins `mirage-crypto-rng-mirage` as well, not just the three packages
`ocaml-mpc` itself depends on.
