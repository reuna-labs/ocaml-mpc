# ocaml-mpc

Threshold signatures and multi-party computation for OCaml, built to run in a
MirageOS/Solo5 unikernel.

The first protocol is **FROST** — the two-round threshold Schnorr signature scheme of
[RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html): distributed key generation,
two-round signing, and signature-share verification with identifiable abort. A group of
*n* parties holds independent key shares, any *t* of them can sign, and **the complete
signing key never exists in any one place at any point in time** — not during key
generation, not during signing, not in memory.

```
opam pin add mpc git+https://github.com/reuna-labs/ocaml-mpc.git
```

## Status

Two ciphersuites are implemented — **FROST(Ed25519, SHA-512)** and
**FROST(secp256k1, SHA-256)** — both verified against RFC 9591's published test vectors
and cross-checked against ZcashFoundation/frost, with an Lwt transport, Unix sockets and
a Solo5 unikernel. Threshold ECDSA is not here yet; see [CHANGES.md](CHANGES.md).

This has not been audited. Read [What this does and does not
guarantee](#what-this-does-and-does-not-guarantee) before using it to hold anything
that matters.

## What it looks like

```ocaml
module Suite = Mpc_ed25519.Suite
module Keygen = Mpc_frost.Keygen.Make (Suite)
module Sign   = Mpc_frost.Sign.Make (Suite)

(* Randomness is a capability, not a dependency: the core cannot reach an ambient
   generator, so it asks for one. *)
let rand = Mpc.Rand.v Mirage_crypto_rng.generate

(* Both protocols are pure state machines. *)
let session = Result.get_ok (Keygen.create rand config) in
let session, events = Result.get_ok (Keygen.step session Mpc.Session.Start) in
...
```

## Packages

| package | what it is |
|---|---|
| `mpc` | the protocol core, plus `mpc.ed25519` and `mpc.secp256k1` (the ciphersuites) and `mpc.frost` (the protocol). No I/O of any kind. |
| `mpc-lwt` | framing, a driver that owns the clock, and an AEAD seal for the DKG's private payloads. Functorised over `Mirage_flow.S`, so the same code runs over TCP, vsock or TLS. No dependency on unix. |
| `mpc-unix` | sockets, address parsing, full-mesh connection establishment. The only package permitted to depend on unix. |

Splitting them this way is what lets the core and the transport cross-compile to a
Solo5 unikernel unchanged, and CI checks the boundary by inspecting each library's
declared dependencies rather than grepping for module names.

Lwt rather than Eio is a constraint, not a preference: MirageOS has no Eio backend, so
a unikernel-capable transport has to be Lwt-based.

## Design

**Sans-IO.** The protocol core is a pure transition function
`step : t -> input -> (t * events, error) result`. No clock, no scheduler, no sockets,
no ambient randomness. Time enters only as a `Timeout` the driver chooses to inject;
randomness only as a function the caller supplies. The same code therefore drives a
Unix process, a unikernel, and a deterministic in-memory simulator that replays an
entire n-party run — adversarial message schedule included — from a single seed. Nothing
under `lib/` may reference `Unix`, `Lwt`, `Async` or `Thread`, and CI enforces that.

**Generic over the group.** FROST is written once against a `CIPHERSUITE` module type
(RFC 9591 §3.1); a ciphersuite is an instance, not another protocol implementation. The
two present share very little — short Weierstrass against twisted Edwards, big-endian
scalars against little-endian, 33-byte compressed points against 32-byte, RFC 9380
`hash_to_field` against a wide reduce — and adding the second one required no change to
`mpc` or `mpc.frost`. Ristretto255 or P-256 would be another instance.

**Which suite to use.** secp256k1 if you are signing for Bitcoin or Ethereum, or if you
will later want threshold ECDSA — it is the one that satisfies `CIPHERSUITE_CT` (see
below). Ed25519 if you want signatures any RFC 8032 verifier accepts, or a unikernel
with no GMP anywhere in it.

**Nonce reuse is prevented structurally.** Reusing a FROST nonce across two messages
leaks the signing share outright — it is the one bug that makes a threshold library
actively dangerous. So: no function takes a nonce as an argument; the nonce lives in a
*mutable* cell that is wiped before the signature share is returned; `Sign.t` has no
serialization function and a signing session must not survive a restart; and a retry
after an abort is a new session, never a resume.

The mutable cell is the subtle part. `step` is a pure function over an immutable state
value, so a caller can retain the state from before a step and call `step` again with a
*different* message — and get a second share from the same nonce. Immutability cannot
prevent that. A shared mutable cell can: the replay finds it already erased.

**Abort destroys the right things.** In signing there is nothing to roll back — the
long-lived share is read-only throughout — so abort must *not* touch it; wiping a share
on a network fault would turn a transient problem into permanent key loss. What abort
destroys is the ephemeral nonce. The DKG is the opposite case: an abort after round 2
would otherwise leave a partial sum that is a linear function of other parties' secrets
and that combines across aborted runs, so the DKG is atomic — either everyone finishes
or nobody keeps anything.

**One session per flow.** A driver owns each flow's byte stream for the lifetime of one
session, and the stream carries no session demultiplexing. Do not run two sessions over
the same flow, concurrently or in succession — two readers split the bytes between them,
and sequentially a peer that starts early has its first frames eaten by the previous
session's reader. Establish fresh flows per session, or add a demultiplexing layer. A
retry after an abort is a new session and needs new flows too.

## What this does and does not guarantee

**Constant time, where it counts.** In FROST, arbitrary-point scalar multiplication is
applied only to *public* scalars — binding factors, participant identifiers, the
challenge, Lagrange coefficients. The only secret-dependent operations are scalar
arithmetic and *base-point* multiplication, and on both suites those are constant time:
`sc_muladd` and `ge_scalarmult_base` on Ed25519, fiat-crypto's n-field and ECCKiila's
comb on secp256k1. That claim is enforced, not asserted: `Element.scalar_mul` has an
allowlist of call sites, each annotated with why its scalar is public, and CI fails on
any use outside it.

The two suites differ in one way that matters later. On secp256k1, `Element.scalar_mul`
is *also* constant time — ECCKiila's regular-wNAF ladder, with no zero digits, a fixed
operation sequence and full-scan table lookups — so `Mpc_secp256k1.Suite` satisfies
`CIPHERSUITE_CT`. `Mpc_ed25519.Suite` does not, because its variable-base multiply
routes through `ge_double_scalarmult_vartime`. FROST tolerates that; threshold ECDSA
will not, since it multiplies arbitrary points by secret scalars — and the
`CIPHERSUITE_CT` functor argument is what makes instantiating it over the wrong suite a
compile error rather than a silent leak.

Both are also built on the *constant-time* secp256k1 in `mirage-crypto-ec` rather than
the zarith one in `mirage-crypto-blockchain`, which implements the same group but says
in its own documentation that it is not hardened. That one appears here only as an
independent implementation to cross-check against in tests.

**But OCaml offers no constant-time guarantees of its own,** and this library does not
pretend otherwise:

* **Secrets are held in buffers that can be overwritten, and are.** The DKG polynomial
  lives in one contiguous `Mpc.Secret.t`, and the running values of a polynomial
  evaluation, a share sum and a signature share are computed in a wipeable accumulator
  (`Scalar.Acc`) rather than as a chain of immutable strings. Each is erased when it
  finishes, and there are shipped tests asserting that rather than assuming it.

  What that does **not** amount to: `Acc.reveal` materialises a value that escapes the
  buffer — it is named for that — and OCaml's collector may copy a buffer while
  promoting it, leaving a copy nothing can reach. The claim is that this bounds the
  number of unerasable copies of a secret and erases the long-lived ones, not that it
  reaches zero. A language with no control over its own memory cannot promise more.
* No formal verification has been done here. The field and group arithmetic underneath
  comes from fiat-crypto (machine-checked) and BoringSSL, but this library's own code
  has not been verified.
* There *is* a timing harness (`test/timing/`), and it is a negative test: it can find
  leakage, not prove its absence. It found one — `Scalar.invert` returned early on a
  zero input — which is now fixed. It carries a positive control and reports
  INCONCLUSIVE rather than success when that control goes undetected, because an
  instrument too blunt to see anything reports success on everything.

**FROST signing has no identifiable abort for non-participation.** A bad *signature
share* is attributed to exactly the party that produced it. A party that simply refuses
to participate is indistinguishable from one that is offline. That is inherent to the
scheme.

**The transport must be authenticated and confidential.** FROST assumes it; this
library does not provide it. DKG round-2 messages carry secret shares, and
`Msg.encode` refuses to serialise one without a seal function — a structural reminder,
not a substitute for reading this paragraph.

**The DKG is not covered by any published test vector.** RFC 9591 specifies it in an
appendix, publishes none, and leaves its proof-of-knowledge challenge hash open. This
implementation matches ZcashFoundation/frost byte for byte and `test/interop/run.sh`
checks that on every run — but a second implementation agreeing is weaker evidence than
a specification with vectors, and changing the construction later would invalidate the
provenance of any key material already generated.

## Testing

```
dune build @fmt && dune runtest        # everything below except the three that follow
dune exec test/timing/timing_ct.exe    # minutes, and noisy on a busy machine
./test/interop/run.sh                  # cross-checks against ZcashFoundation/frost
./mirage-smoke/build.sh                # Solo5 cross-build and boot, needs Docker
```

`dune runtest` covers the core suite, the end-to-end socket tests, the unikernel body
run on the host, and three CI guards: no I/O in the core or the transport, and the
`Element.scalar_mul` allowlist. It includes: RFC 9591 Appendix E.1 known-answer tests
reproducing *every* published intermediate byte for byte; cross-verification of every
aggregated signature against `Mirage_crypto_ec.Ed25519.verify`, an implementation that
knows nothing about threshold signing; rejection of all eight small-order points and of
non-canonical point encodings; full DKG-then-sign runs under in-order, reversed and
seeded-shuffled schedules; message duplication and party crashes; nonce-reuse replay;
cross-session replay; equivocation and bad-share attribution; hostile-input fuzzing of
the codec; RFC 9380 `expand_message_xmd` against its own vectors, long-DST cases
included; randomised properties with shrinking, including one no example-based test
can state — over arbitrary party counts, thresholds, signer subsets and message
schedules, a run yields a signature that verifies or none at all, never a wrong one;
and a three-node distributed key generation followed by threshold signing over real
sockets, with the DKG's private shares sealed.

Two checks live outside `dune runtest` because they need things a build should not
assume. `test/interop/run.sh` validates against
[ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) in three directions —
their signature under our verifier, their key material through our signing under their
verifier, and their DKG round 1 under our proof-of-knowledge verifier — and needs a Rust
toolchain. `mirage-smoke/build.sh` cross-compiles to Solo5 and boots the result under
`solo5-spt`, and needs Docker.

## Licence

ISC — see [LICENSE.md](LICENSE.md).
