# Threshold ECDSA — design plan

Status: **plan only**. Nothing here is implemented.

Last refreshed August 2026, after the November 2025 CGGMP21 disclosures.

This is deliberately separate from the FROST work. Threshold ECDSA is not "FROST for a
different curve"; it is a substantially larger and riskier construction, and the honest
first sections of this document are the ones arguing about whether to build it, and if
so which construction.

---

## 1. Why this is not a continuation of the FROST work

FROST is threshold Schnorr, and Schnorr signatures are linear in the secret:
`z = d + e·rho + lambda·s·c`. Each party computes its contribution locally and the
shares add. That linearity is why it fits in two rounds, needs no zero-knowledge proofs,
and was implementable here against primitives that already existed.

ECDSA is not linear. Signing computes `s = k^-1 · (H(m) + r·x)`, and a threshold protocol
must produce `k^-1` and the product `k^-1·x` without any party learning `k` or `x`. Every
practical construction does that with **multiplicative-to-additive conversion (MtA)**,
and the two families differ in how:

- **Paillier-based** (GG-family, CGGMP21/24): additively homomorphic encryption, plus a
  stack of zero-knowledge range proofs to stop a malicious party feeding in out-of-range
  values.
- **OT-based** (DKLs18/19/23): oblivious transfer and vector oblivious linear evaluation.
  No Paillier, no range proofs, no safe primes.

`mpc`'s Shamir, session machine, transcript, codec and abort discipline carry over to
either. The cryptography does not, and OCaml has none of it in either family.

---

## 2. The argument against building it, stated first

Threshold ECDSA has a bad safety record. It is not a record of exotic theoretical
breaks; it is a record of **key-extraction bugs in shipped, audited, production
libraries holding real funds** — and, as of November 2025, of the specifications
themselves being wrong.

### What happened to CGGMP21, in November 2025

Two vulnerabilities, disclosed 24 November 2025
([CVE-2025-66017](https://feedly.com/cve/CVE-2025-66017),
[RUSTSEC-2025-0130](https://rustsec.org/advisories/RUSTSEC-2025-0130.html),
[Dfns write-up](https://dfns.co/article/cggmp21-vulnerabilities-patched-and-explained)):

1. **A missing check in the Paillier–Blum modulus proof (Π_mod)**, used during auxiliary
   key generation. **A single malicious party can extract the full private key.** Found
   by Arik Galansky (Fireblocks).

   The critical detail: the check *was present in the security proof and absent from the
   paper's written protocol* — CGGMP21 Figure 16, page 36, against CGGMP24 Figure 12,
   page 31. **An implementation that followed the published protocol faithfully was
   vulnerable.**

2. **Signature forgery from presignatures combined with raw signing.** An attacker who
   learns a presignature's public component submits a crafted hash `h'`, receives a
   signature on it, and transforms that into a valid signature on a message of their
   choosing. With HD wallet derivation this reduces security to roughly **85 bits**.
   Independently found by Antoine Urban (Dfns), May 2025.

   This one **cannot be fixed at the protocol level.** CGGMP24 addresses it by making
   the dangerous combination unrepresentable in the API, which required breaking changes.

Patched in `cggmp21` v0.6.3 (the minimal fix for the first issue only) and `cggmp24`
v0.7.0-alpha.2 (both, plus additional defensive checks).

### The earlier record

- **TSSHOCK** (2023) — key extraction from several production libraries, from missing or
  improperly bound range proofs in MtA.
- **Alpha-Rays** (2021) — full key extraction via a malicious party choosing an
  out-of-range Paillier modulus that the verifier's proofs did not constrain.
- Multiple "0-value" and small-parameter attacks against MtA where a proof was checked
  but not bound to the right transcript.

### What changed about the shape of the risk

The 2021–2023 attacks fit a pattern this plan was originally designed against: *the
scheme was sound and the implementation omitted or mis-bound a proof.* The defence is
adversarial testing — feed every proof a malformed witness and require rejection.

**The 2025–2026 findings are a different and worse shape.** In CGGMP21's Π_mod, and in
DKLs23's VOLE parameters (§3), a **faithful implementation of the published paper is
insecure**. No amount of malformed-input testing finds that, because the implementer
does not know the property is supposed to hold. Only tracking errata, implementing
against the newest revision, and differential-testing against an audited implementation
catch it.

So the recommendation is unchanged in direction and stronger in degree:

> **Do not put this on a key that holds value without an external audit by people who do
> threshold ECDSA specifically.** And note that even that is not sufficient: the CGGMP21
> implementations broken in 2025 had been audited. The specification was the problem.

**If Taproot is acceptable, FROST over secp256k1 is already implemented here, matches
RFC 9591's vectors, interoperates with ZcashFoundation/frost, and is far safer.** It has
no Paillier, no range proofs, no OT, and a two-round protocol small enough to read. The
case for threshold ECDSA is compatibility with pre-Taproot Bitcoin and with Ethereum's
`ecrecover` — not security.

---

## 3. Choosing a construction

Three candidates, and the choice matters more than anything else in this document.

### CGGMP24 — Paillier, dishonest majority

The current revision of the CGGMP line, and **the only one to pick if going this route**;
CGGMP21 is superseded and known-vulnerable, and the v0.6.3 patch fixes only the first
issue.

- Identifiable abort throughout. `Mpc.Session.abort` already carries `culprits`.
- Dishonest majority: secure with up to `t-1` corruptions out of `t`.
- Widely deployed, so interoperating with an existing custody stack is plausible.
- Costs: Paillier with safe primes, Ring-Pedersen parameters, and Π_enc, Π_log*,
  Π_aff-g, Π_dec, Π_mod, Π_prm, Π_fac. That stack is the bulk of the work and,
  historically, the bulk of the vulnerabilities.

### DKLs23 — oblivious transfer, dishonest majority

[Doerner, Kondi, Lee and shelat, *Threshold ECDSA in Three Rounds*, eprint
2023/765](https://eprint.iacr.org/2023/765). Three rounds, and **no Paillier, no safe
primes and no range proofs at all** — the entire class of hazard that produced Alpha-Rays,
TSSHOCK and CGGMP21's Π_mod bug simply does not exist here. Trail of Bits, reviewing one
of the first implementations, observed that
[OT-based systems generally prove less error-prone than Paillier-based ones](https://blog.trailofbits.com/2025/06/10/what-we-learned-reviewing-one-of-the-first-dkls23-libraries-from-silence-laboratories/).

It is not a free lunch, and the same review is the best available catalogue of why:

- The specification is four dense pages of nested sub-protocols (`F_Com`, `F_RVOLE`,
  `F_Zero`) defined across several papers.
- It gives the implementer freedom over base OT, OT extension and pairwise
  multiplication. Wrong choices compound.
- Real bugs found in a real implementation: nonce reuse in the encryption channel
  enabling key destruction; selective-abort handling that panicked instead of
  attributing blame, enabling key destruction or key extraction; and a timing leak in
  `eval_pprf`.

And it has its own specification-level problems — plural, and worse than first
reported here. [Asharov, *Revisiting DKLs Threshold ECDSA*, eprint 2026/976 (May
2026)](https://eprint.iacr.org/2026/976) finds **three** independent ways in which
implementing the published protocol faithfully gives an insecure result:

1. **The VOLE gadget-vector parameters are insufficient.** DKLs applies the leftover
   hash lemma as though the gadget vector `g` and the receiver's choice bits `w` were
   independent, but `g` is fixed first, so a malicious Sender can pick the min-entropy
   source *after* seeing it. Confirmed experimentally. The required OT count rises from
   about 376 to about 1400 in the original structure.
2. **The Endemic-OT instantiation is attackable.** The consistency check's challenge is
   derived by hashing the Sender's matrix without binding anything from the OT phase —
   and in an OT-hybrid model nothing binds it, because the parties never observe the
   same values. Under Endemic OT, where a corrupted Sender chooses its own OT inputs, it
   samples the matrix first, derives the challenge from it, and then picks an
   arbitrarily inconsistent matrix. Asharov's words: the attack "completely nullifies
   the verification step". The fix is to use **Sender-Random OT**, which makes the
   choice of OT flavour a security decision rather than an efficiency one.
3. **The masking parameter ρ is misprinted**, giving 2 where 1 suffices.

The first also affects DKLs18 and DKLs19. Same shape as CGGMP21's Π_mod: faithful
implementation, insecure result — and here, three times over.

Asharov gives three sound instantiations with different bandwidth/round trade-offs, so
this is a solved problem rather than an open one. But it means **DKLs23 must be
implemented from two papers, not one**, which is exactly what milestone D0 exists to
record.

For OCaml specifically, DKLs23 means building an OT extension and a VOLE. Neither exists
in this tree. It is a different stack, not obviously a smaller one.

### KU23 — honest majority

[Katz and Urban, 2023](https://www.dfns.co/article/ku23), Dfns's default protocol and
proposed for NIST standardisation. Extremely fast — batched presignatures at ~1.3 ms
amortised — and unaffected by both CGGMP21 issues.

**But it assumes an honest majority of servers**, where CGGMP24 and DKLs23 tolerate a
dishonest majority. That is a much stronger assumption and rules it out for the classic
custody setting where each share sits with a mutually distrusting party. It is the right
choice for a single operator running `n` servers it controls, and the wrong one for
`t`-of-`n` across organisations. Do not compare it to the other two without stating
which threat model is being bought.

### Recommendation

1. **First, re-ask whether FROST-secp256k1 suffices.** It is implemented, vectored and
   interoperating. Most of the reasons to want threshold ECDSA are compatibility, not
   capability.
2. If ECDSA is genuinely required: **DKLs23 as corrected by Asharov** — specifically
   Variant II with Sender-Random OT. It removes the entire Paillier and range-proof
   stack, and that stack is where the field's key extractions have come from. See
   [`dkls23-specification-pin.md`](dkls23-specification-pin.md) for the exact revisions,
   parameters and departures.
3. **CGGMP24** if interoperating with an existing CGGMP deployment is a hard
   requirement. Never CGGMP21.
4. **Do not implement presigning initially, and never combine it with raw signing.** The
   earlier version of this plan recommended presigning as "the property custody systems
   actually want" — vulnerability 2 above is precisely that combination. If presigning is
   added later, the API must make signing a hash the caller has not shown the protocol
   *impossible to express*, not merely discouraged.

---

## 4. Package layout

Common to either construction:

```
mpc.ecdsa        the protocol: keygen, refresh, signing
                 functorised over Mpc.Group.CIPHERSUITE_CT
```

For DKLs23:

```
mpc-ot           base OT and OT extension, own opam package
  base_ot.ml       e.g. Simplest OT / endemic OT
  ot_ext.ml        KOS or SoftSpokenOT
  vole.ml          random VOLE, with Asharov's parameters
```

For CGGMP24:

```
mpc-paillier     own opam package -- zarith, and therefore GMP
  paillier.ml      safe-prime keygen, enc/dec, homomorphic add and scalar-mul
  ring_pedersen.ml parameters plus Pi_prm
mpc.zk           the proofs: Pi_enc, Pi_log*, Pi_aff-g, Pi_dec, Pi_mod, Pi_fac
```

**Whichever is chosen, its heavy dependency lives in its own opam package.** Paillier
pulls in zarith and hence GMP; keeping it out of `mpc` is what preserves the property
that an Ed25519 or secp256k1 FROST unikernel needs no GMP at all. The no-I/O guard in
`test/dune` should grow a companion check that nothing in `mpc`, `mpc.ed25519`,
`mpc.secp256k1` or `mpc.frost` depends on it.

---

## 5. What is reused unchanged

- `Mpc.Session` — inputs, events, the slot table, equivocation detection, the abort and
  wipe discipline. More rounds, not different plumbing.
- `Mpc.Shamir` — both constructions use additive shares at signing time, converted from
  Shamir shares by the existing `lagrange`.
- `Mpc.Codec`, `Mpc.Rand`, `Mpc.Secret`, `Scalar.Acc`.
- `Mpc.Group.CIPHERSUITE_CT` — **the ECDSA functor takes this, not `CIPHERSUITE`.**
  Threshold ECDSA multiplies arbitrary points by secret scalars, which FROST never does.
  `Mpc_secp256k1.Suite` satisfies it; `Mpc_ed25519.Suite` does not. Instantiating over
  the wrong suite is a compile error rather than a silent side channel.
- `Mpc_lwt` transport and driver, unchanged.

---

## 6. Milestones

Written for DKLs23, the recommended route. The CGGMP24 variant replaces D1–D2 with the
Paillier and proof stack and is roughly twice the work.

**D0 — pin the specification. ✅ Done:**
[`docs/dkls23-specification-pin.md`](dkls23-specification-pin.md).

Records both papers and their revision dates, the three places the published protocol is
deliberately *not* followed, the chosen variant and every parameter with its derivation.
This is not bureaucracy: "CGGMP21 Figure 16 page 36" versus "CGGMP24 Figure 12 page 31"
was precisely the difference between vulnerable and not, and DKLs has the same hazard in
three places. Every pinned constant should get a test that fails if it changes without
that document changing with it.

**D1 — oblivious transfer.** Base OT and an OT extension, in the **Sender-Random**
flavour required by §3.2 of the pin — not Endemic OT, whose use here is attackable.
*Done when:* correctness and malicious-security properties hold under property tests;
the extension is cross-checked against an independent implementation; the flavour
actually delivered is checked against what the VOLE proof requires rather than assumed;
and the timing harness covers it, since Trail of Bits found a timing leak in exactly this
layer.

**D2 — VOLE.** Asharov's **Variant II** with m = 696 and ρ = 1, not the 2023 paper's
parameters. *Done when:* the constants match the pin and a test fails if they drift;
`log q ≥ λ_c + 2·log m` is checked rather than assumed; and correctness is cross-checked
against an independent implementation.

**D3 — key generation and refresh.** *Done when:* `n` parties agree on a public key; any
`t` shares interpolate to a secret whose public image matches; refresh preserves the
public key while changing every share; a corrupted contribution is attributed.

**D4 — signing.** Asharov's §6 two-round variant, which tolerates `β` arriving late and
so keeps Variant II from costing an extra round — not the signing protocol as printed in
DKLs. *Done when:* signatures verify under `Mirage_crypto_ec.P256k1.Dsa`, an
implementation that knows nothing about threshold signing; published test vectors
reproduce; and the fault battery from the FROST work — drop, crash, reorder, duplicate,
equivocation, corrupt share — reports the right culprits.

**D5 — identifiable abort, as a first-class milestone.** Trail of Bits found an
implementation that panicked instead of attributing blame, which enabled *both* key
destruction and key extraction depending on who got blamed. *Done when:* every
detectable deviation names exactly the responsible party, and a test asserts that no
input causes a panic in place of an abort.

**D6 — cross-implementation.** Extend `test/interop/` against an audited Rust
implementation, in both directions, as the FROST work does. Given how the FROST vector
situation turned out, **check any third-party vectors against the paper before trusting
them**, and prefer live cross-checks to copied files.

---

## 7. Risks, in the order they will actually bite

1. **The specification may be wrong.** This is now demonstrated for both candidate
   constructions. Mitigation: D0, tracking errata and advisories for the chosen
   construction as an ongoing obligation rather than a one-off, and D6.
2. **A missing or mis-bound proof or check leaks the key silently.** The protocol
   completes, the signature verifies. Mitigation: adversarial test catalogues, and every
   proof or commitment bound to a transcript including the session identifier and the
   prover's identifier.
3. **Presigning is a security-relevant API decision, not an optimisation.** See §3.
4. **Side channels.** For DKLs23, in the OT extension and PPRF evaluation. For CGGMP24,
   in Paillier decryption, which exponentiates with the secret primes and needs blinding
   — `Mirage_crypto_pk.Rsa` already does this for RSA-CRT and should be read first.
   zarith is not constant time, which is exactly why FROST kept it off the secret path;
   on the CGGMP route it cannot be avoided.
5. **Safe-prime generation is slow** (CGGMP route only) — seconds to minutes at 2048
   bits. That shapes the API: key generation must be resumable and must not block a
   scheduler.
6. **GMP on Solo5 returns** (CGGMP route only). Solved in this tree already via nethsm's
   `gmp.dev` pin and `GMP_TARGET=kabylake-solo5-none`, but an `mpc-ecdsa` unikernel
   inherits the whole apparatus the FROST one skips.
7. **Scale.** Larger than M1–M3 combined either way.

---

## 8. What would make this trustworthy rather than merely finished

- A pinned specification revision and a written parameter justification (D0).
- Adversarial catalogues for every proof and every parameter validation — necessary, and
  now known to be **insufficient** on its own.
- **Differential testing against an audited implementation, in both directions.** This
  is the only defence listed here that catches a specification-level fault, because it
  compares against someone who read the same paper differently.
- `ctgrind` on a Linux runner over the secret-dependent paths. The timing harness in
  `test/timing/` measures; it does not prove.
- An external audit before any of it touches value — while noting that the CGGMP21
  implementations broken in 2025 had been audited too.

Absent those, the honest description is: an implementation of a threshold ECDSA protocol
that reproduces its test vectors and interoperates, and that nobody should trust with
money.
