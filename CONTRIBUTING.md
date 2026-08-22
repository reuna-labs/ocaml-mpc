# Contributing

## Conventions

* `dune build @fmt` must be clean; the ocamlformat version is pinned in
  `.ocamlformat` and CI installs exactly that version.
* Nothing under `lib/` may reference `Unix`, `Lwt`, `Async`, `Thread`, or
  any other I/O. CI enforces this with `test/no_io_guard.sh` and a Solo5
  cross-build.
* Every module gets an `.mli`. Public functions return `result`; exceptions
  do not cross a public boundary.
* Test vectors live in `test/vectors/` and every file is recorded in
  `test/vectors/README.md` with its upstream URL, revision and licence.

Two further rules are specific to a threshold-signature library.

## Every use of `Element.scalar_mul` must be justified

`Element.scalar_mul` — multiplication of an arbitrary point by a scalar — is
**variable time** in the Ed25519 ciphersuite: it routes through BoringSSL's
`ge_double_scalarmult_vartime`. FROST tolerates that only because it applies the
operation exclusively to *public* scalars: binding factors, participant identifiers,
the challenge, Lagrange coefficients. Secret scalars meet the group only through
`Element.scalar_mul_base`, which is constant time.

That is a property of the call sites, not of the types, so it is checked rather than
asserted. `test/scalar_mul_guard.sh` runs as part of `dune runtest` and fails if a file
uses `Element.scalar_mul` without appearing in `test/scalar_mul_allowlist.txt`. Adding
a call site means adding a line there saying why *your* scalar is public. If you cannot
say why, use `scalar_mul_base` or restructure.

The stronger enforcement — a phantom type `[ `Public | `Secret ] scalar` making it a
compile error — was considered and deferred: it infects every signature in `Shamir`,
`Vss` and `Frost` for a property currently held by four call sites. Revisit it when
threshold ECDSA lands, since that is where secret scalars start reaching `scalar_mul`
and the trade inverts.

## Anything derived from a share or a nonce lives in a `Secret.t`

…and is wiped on every exit path, including the exceptional one. Note honestly what
that buys: `Mpc.Secret` owns mutable `bytes` and `wipe` really overwrites them, but a
`Scalar.t` returned by a C stub is an immutable `string` that cannot be overwritten
portably, so `Shamir.wipe` only drops references. Closing that gap needs
`scalar_muladd_into`-style primitives writing into caller-owned buffers, which is a
pending change to the mirage-crypto fork (see *Upstream* below). Do not describe
current behaviour as more than it is.

## Normative encodings and the wire format are separate

`lib/frost/encoding.ml` holds RFC 9591's *normative* encodings — the byte strings that
feed the hash functions. `lib/frost/msg.ml` holds our wire format. They share no
helpers and are tested separately. Conflating them is the most common source of
"our signatures don't verify in the other implementation".

## Upstream

`Mirage_crypto_ec.Ed25519.Primitive` is an addition in the Reuna fork of mirage-crypto
and is not upstream, so `mpc.opam.template` pins the fork by commit and this package
cannot go to opam-repository until that lands.

**Pin the whole family from one source.** The fork has diverged from the released
packages: an upstream `mirage-crypto-rng-mirage` built against the fork's
`mirage-crypto-rng` fails with `Unbound value entropy_test`. Anything that needs
rng-mirage — the unikernel does — must pin it too, not just the three packages
`ocaml-mpc` itself depends on. `mirage-smoke/build.sh` does.

Three changes are wanted in the fork.

1. **`scalar_muladd_into` / `scalar_reduce_into` / `scalar_mult_base_into`** — variants
   writing into a caller-supplied `bytes`, so secret scalars can stay wipeable for
   their whole lifetime instead of becoming unerasable immutable strings. The C stubs
   already write into an out-parameter; only the OCaml wrappers allocate.

   *Status: landed.* Committed on the fork's `ec-into-and-x25519` branch, which
   `mpc.opam.template` now pins. The allocating functions were reimplemented on top of
   the new ones so there is one code path, and the EC suite passes.

   `ocaml-mpc` uses them indirectly so far: `Shamir` holds its polynomial in a single
   wipeable buffer, so `Shamir.wipe` really overwrites the durable secret. Reads still
   deserialise through `Scalar.t`, an immutable string, so transient copies remain
   unerasable. Closing that needs the `GROUP` signature to surface `*_into`-style
   operations — the primitives now exist, the abstraction does not expose them.

2. **A constant-time secp256k1 group API.** *Status: landed*, as `P256k1.Primitive` on
   the same branch (commit `92ff0d0`). Almost entirely exposure of code that was already
   there — fiat-crypto scalar arithmetic in `nsecp256k1_stubs.c` and ECCKiila's ladder —
   plus one thin wrapper around the existing `point_add_proj`. `mpc.secp256k1` is built
   on it.

3. **`Make_point_base.of_octets` raises where the API promises a `result`.** A
   `0x02`/`0x03` prefix is dispatched to `decompress` with no length check, so
   `P256k1.Dsa.pub_of_octets "\x02"` raises `Invalid_argument` out of `String.sub`.
   Untrusted wire input can therefore raise from a function typed to return
   `(_, error) result`. `Primitive.point_of_octets` length-checks first and is not
   affected, and `ocaml-mpc` only uses the latter.

4. **Length checks on the Ed25519 primitives.** The C reads exactly 32 bytes from each
   argument without checking, so a shorter OCaml string is a heap over-read. Change (1)
   fixes this for the three functions it reimplements; `verify_double_base`'s `k` and
   `s`, and both of `point_add`'s inputs, remain unchecked. `ocaml-mpc` is not exposed
   — every value it passes is produced by its own validated constructors, and
   `Mpc_ed25519.Element` checks defensively anyway before the point operations — but it
   is a real bug in the fork and worth fixing there.

## Adding a ciphersuite

A ciphersuite is an instance of `Mpc.Group.CIPHERSUITE`, not another implementation of
the protocol. Adding one means:

1. `lib/<curve>/` — the instance. Look at `lib/secp256k1/` rather than `lib/ed25519/`
   for a template: it is the one that had to deal with a different endianness, a
   different point width, and `hash_to_field`, so it shows where the abstraction's
   seams actually are.
2. `test/suites_<curve>.ml` — instantiate `Suite_arith`, `Suite_vectors` and
   `Suite_e2e`, and supply an *independent* verifier for the reference check. If the
   only verifier available is the code under test, say so rather than passing a
   circular one.
3. RFC 9591 vectors in `test/vectors/`, from the RFC text — see that directory's README
   for why not from a third-party copy.
4. Add the directory to the no-I/O guard's `core` list in `test/dune`.

If the suite's `Element.scalar_mul` is constant time in its scalar, declare
`CIPHERSUITE_CT`. If it is not, do not — that signature is what will keep threshold
ECDSA off a curve implementation that cannot carry it.

## Interoperability with other implementations

RFC 9591 fixes the signing path completely and it is covered by the vectors in
`test/vectors/`. It does **not** fix the two-round DKG: that lives in an appendix, has
no published test vectors, and leaves the proof-of-knowledge challenge hash open. So
agreeing with the specification is not enough to agree with anybody.

`ocaml-mpc` matches ZcashFoundation/frost byte for byte:

```
c_i = HDKG( SerializeScalar(id) || SerializeElement(phi_i0) || SerializeElement(R_i) )
```

(`frost-core-2.2.0/src/keys/dkg.rs:413`, `frost-ed25519-2.2.0/src/lib.rs:211`.)

`test/interop/run.sh` checks this and two signing directions against their
implementation, for both ciphersuites, on every run. If you change the challenge construction, that script is
what will tell you — and changing it invalidates the provenance of any key material
already generated, so treat it as a breaking change to stored state, not to code.
