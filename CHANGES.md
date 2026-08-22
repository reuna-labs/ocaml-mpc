## v0.1.0 (unreleased)

First release. FROST (RFC 9591) over the Ed25519 ciphersuite.

* `mpc` — the protocol core, free of I/O: a `GROUP`/`CIPHERSUITE` abstraction, Shamir
  secret sharing, Feldman verifiable secret sharing, a big-endian fixed-width binary
  codec, wipeable secrets, randomness as an explicit capability, and a sans-IO session
  state machine with a bounded slot table.
* `mpc.ed25519` — FROST(Ed25519, SHA-512), over `Mirage_crypto_ec.Ed25519.Primitive`.
  No bignum, hence no GMP.
* `mpc.frost` — RFC 9591 Section 5 signing, the normative encodings, trusted-dealer key
  generation (Appendix C), the two-round Pedersen DKG (Appendix D), and two-round
  threshold signing as state machines with identifiable abort.

Verified against RFC 9591 Appendix E.1: every published intermediate — nonces,
commitments, binding-factor inputs, binding factors, signature shares and the final
signature — reproduces byte for byte, and aggregated signatures are accepted by
`Mirage_crypto_ec.Ed25519.verify`.

Transports:

* `mpc-lwt` — bounded length-prefixed framing, a driver that owns the clock and turns
  the sans-IO core into a running participant, and an AEAD seal for the DKG's private
  payloads. Functorised over `Mirage_flow.S`, so the same code runs over TCP, vsock or
  TLS. No dependency on unix.
* `mpc-unix` — sockets, address parsing and full-mesh connection establishment. The
  only package permitted to depend on unix.
* `mirage-smoke/` — a compute-only Solo5 unikernel that re-checks the RFC 9591 vector
  and runs a full DKG-then-sign in-kernel. The same file runs on the host under
  `dune runtest`.

Also in this release:

* The coordinator now broadcasts the aggregated signature, so every signer reaches a
  terminal state and verifies the result for itself rather than trusting the
  coordinator's claim.
* `Scalar.invert` no longer returns early on zero. The chain runs unconditionally, so
  the operation does not leak whether its input is zero.
* A timing harness (`test/timing/`) measuring the operations applied to secret
  scalars, with a positive control: it reports INCONCLUSIVE rather than success when it
  fails to detect leakage it is known to be able to see.

Secret handling:

* `Scalar.Acc` — a wipeable accumulator in the group abstraction, over the fork's
  `scalar_muladd_into`. Polynomial evaluation, DKG share summation and signature-share
  computation now run in overwritable buffers and erase them, instead of leaving one
  unerasable string per intermediate.
* `Shamir` holds its polynomial in a single `Secret.t`, so `Shamir.wipe` overwrites
  bytes rather than dropping references, and every accessor raises afterwards.

Validation:

* `test/interop/` — cross-implementation checks against ZcashFoundation/frost 2.2.0.
  This settled the DKG proof-of-knowledge construction, which RFC 9591 leaves open:
  ocaml-mpc now matches `frost-core` byte for byte, and no longer binds the session
  identifier into that challenge.
* `test/suite_props.ml` — randomised properties with shrinking, including three codec
  fuzzers and a protocol-level invariant over arbitrary party counts, thresholds,
  signer subsets and schedules.
* The Solo5 unikernel has been cross-compiled and booted, not merely written.

Second ciphersuite:

* `mpc.secp256k1` — FROST(secp256k1, SHA-256), over a constant-time secp256k1 group API
  newly exposed in the mirage-crypto fork (fiat-crypto scalar arithmetic, ECCKiila
  scalar multiplication). Every RFC 9591 Appendix E.5 intermediate reproduces byte for
  byte. Unlike the Ed25519 suite it satisfies `CIPHERSUITE_CT`, which threshold ECDSA
  will require.
* `Mpc.Xmd` — RFC 9380 `expand_message_xmd`, which secp256k1 needs for `hash_to_field`
  and Ed25519 does not. Verified against RFC 9380's own vectors including the long-DST
  cases.
* The test suites are functors over the ciphersuite: `Suite_arith`, `Suite_vectors` and
  `Suite_e2e` are instantiated once per curve rather than duplicated. The
  cross-implementation checks and the Solo5 unikernel cover both.

Not yet present: threshold ECDSA.
