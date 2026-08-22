# Cross-implementation validation

Checks `ocaml-mpc` against [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost)
(`frost-ed25519` 2.2.0, from crates.io), the reference Rust implementation.

```sh
./test/interop/run.sh
```

Needs a Rust toolchain and network access to fetch crates, which is why it is not part
of `dune runtest`.

## Why, given the RFC vectors already pass

The RFC 9591 vectors prove we agree with the *specification*. They cannot prove we
agree with another *implementation* about everything the specification leaves to be
inferred — identifier encoding, the exact bytes hashed, scalar and point serialisation
— and for the DKG the specification does not settle the question at all.

## What is checked

Three directions, so neither side is merely trusted.

1. **Their signature, our verifier.** Cheap, and only checks our verification equation.

2. **Their key material, our signing, their verifier.** The strong one: shares this
   code did not produce, run through our round 1, round 2 and aggregation, judged by a
   verifier that has never seen our code. It also checks that each of their verifying
   shares equals `signing_share · G` under our arithmetic — if that failed, the two
   implementations would disagree about scalar encoding and nothing after it would mean
   anything.

3. **Their DKG round 1, our proof-of-knowledge verifier.** This is the one that could
   not be checked any other way.

## The DKG question this settled

RFC 9591 specifies the two-round DKG in an appendix, publishes **no test vectors** for
it, and does not fix the proof-of-knowledge challenge hash. So agreeing with the
specification is not enough to agree with anybody.

`frost-core` computes:

```
c_i = HDKG( SerializeScalar(id) ‖ SerializeElement(phi_i0) ‖ SerializeElement(R_i) )
```

with `HDKG(m) = H2S(SHA-512(contextString ‖ "dkg" ‖ m))` for FROST(Ed25519, SHA-512)
— see `frost-core-2.2.0/src/keys/dkg.rs:413` and `frost-ed25519-2.2.0/src/lib.rs:211`.

An earlier version of `ocaml-mpc` also bound the session identifier into that preimage.
That has been dropped: it bought replay protection the message header already provides
— every message carries the session id and the session machine checks it before doing
any cryptographic work — at the price of interoperating with nothing. Check 3 is what
holds the two constructions together from now on.

## Provenance

- `rust/` is ours, not vendored. It depends on `frost-ed25519 = "2"` from crates.io and
  contains no code from that project; `Cargo.lock` pins the exact versions a run used.
- No test vectors are copied here. Every value is generated fresh on each run, which is
  the point: a fixed vector would only re-check what `test/vectors/` already covers.
