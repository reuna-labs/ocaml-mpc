# D0 — pinned specification and parameters for threshold ECDSA

This document exists because of what happened to CGGMP21 in November 2025: a check that
was present in the security proof and absent from the written protocol, so that a
*faithful* implementation of the published paper allowed a single malicious party to
extract the private key. The difference between vulnerable and not was "Figure 16 page
36" versus "Figure 12 page 31".

DKLs has the same problem in three separate places. So before any code is written, this
records exactly which documents are being implemented, exactly which parameters, and
exactly where the published protocol must **not** be followed.

Nothing here is implemented yet. Revisit this file whenever either paper is revised.

---

## 1. Documents

| role | document |
|---|---|
| Base protocol | Doerner, Kondi, Lee, shelat, *Threshold ECDSA in Three Rounds*, [eprint 2023/765](https://eprint.iacr.org/2023/765), **revision of 2023-12-14**, published IEEE S&P 2024 |
| Corrections and parameters | Asharov, *Revisiting DKLs Threshold ECDSA: Enhanced OT-based VOLE and Two-Party Signing*, [eprint 2026/976](https://eprint.iacr.org/2026/976), 2026-05-18 |

**On the name.** The same work is cited as *DKLs23* (by eprint year) and *DKLs24* (by
publication venue). They are not two protocols. This document says **DKLs** and means
the 2023-12-14 revision of eprint 2023/765. Asharov cites it as [DKLs24]; read that as
the same thing.

**The base protocol is not implemented as written.** Section 3 lists the three places it
is departed from and why. Implementing eprint 2023/765 faithfully produces a protocol
with a demonstrated attack.

---

## 2. Setting

- Curve: **secp256k1**, via `Mpc_secp256k1.Suite`, which satisfies
  `Mpc.Group.CIPHERSUITE_CT`. Threshold ECDSA multiplies arbitrary points by secret
  scalars, so `Mpc_ed25519.Suite` — which does not satisfy it — is a compile error here,
  by design.
- `log q = 256` (the group order's bit length; DKLs writes this as `κ`, which collides
  with the common use of `κ` for the computational parameter — this document writes
  `log q` and never `κ` for that quantity).
- Computational security parameter: **λ_c = 128**.
- Statistical security parameter: **λ_s = 60**, matching Asharov's worked examples.

  *Recorded decision:* DKLs suggests λ_s = 80 "as is common in practice"; Asharov's
  concrete parameter counts use s = 60. λ_s = 60 is adopted so that the OT counts below
  are exactly Asharov's, rather than numbers this project derived by re-running an
  analysis it did not write. Raising to λ_s = 80 costs 60 extra OTs under Variant II
  (`3 · 20`) and is a one-line change; if it is made, record it here and re-derive
  rather than assuming linearity elsewhere.

---

## 3. Where the published protocol is not followed

Three independent findings, all from Asharov. Each is a case where implementing eprint
2023/765 exactly gives an insecure result.

### 3.1 The VOLE gadget-vector parameters are insufficient

`π_RVOLE` derives the receiver's random input as `β = ⟨g, w⟩`, where `g ∈ Z_q^m` is a
gadget vector fixed at the start of the session from shared randomness, `w ∈ {0,1}^m` is
the receiver's OT choice-bit vector, and `m` is the number of OTs. DKLs applies the
leftover hash lemma treating `g` and `w` as independent, concluding `β` is `2^-s`-close
to uniform when

```
m >= log q + 2s          (DKLs -- NOT SOUND)
```

which for secp256k1 is about 376 OTs.

**Why it is unsound.** `g` is fixed *before* `w`. The leftover hash lemma says a random
`g` is good for any *fixed* high-min-entropy source; it does not say that for a *fixed*
`g` there is no adversarially chosen source `W̃` for which `g(W̃)` is far from uniform. A
malicious Sender can pick the source after seeing `g`. Asharov confirms this
experimentally over small parameters (their Appendix A): specific `g` values do admit
bad sources that exceed the bound.

This also affects DKLs18 and DKLs19.

### 3.2 The Endemic-OT instantiation is attackable

DKLs proves `π_RVOLE` in the **Endemic OT** hybrid model, in which a corrupted Sender
may choose its own OT inputs. Asharov §4.5 gives a complete attack that "completely
nullifies the verification step".

The consistency check samples a challenge `χ` and requires that inconsistent rows of the
Sender's matrix produce different inner products. DKLs derives `χ` by hashing `Q`
**without binding anything from the OT phase** — and in an OT-hybrid model there is no
transcript that binds it, because the parties only exchange inputs and outputs with the
functionality and never observe the same values. So a corrupted Sender samples `Q`
first, derives `χ` from it, then chooses an arbitrarily inconsistent matrix `A` and
solves for its last column. The check passes.

**Departure: use Sender-Random OT, not Endemic OT.** This is Asharov's modification 1 to
Protocol 4.2, and it is the reason the choice of OT flavour is a security decision here
rather than an efficiency one.

### 3.3 The masking parameter ρ

DKLs specifies `ρ = ⌈log q / λ_c⌉`, which for secp256k1 with λ_c = 128 gives **ρ = 2**.
Asharov observes this "looks like a typo" — the intended quantity is `⌈λ_c / log q⌉` —
and proves **ρ = 1** suffices whenever `log q ≥ λ_c + 2·log m`, which holds comfortably
here (256 ≥ 128 + 2·log₂(696) ≈ 147).

**Departure: ρ = 1**, with that inequality checked in a test rather than assumed.

---

## 4. Which variant is implemented

Asharov gives three sound instantiations. **This project implements Variant II.**

| | condition on m | OTs (log q=256, s=60, λ_c=128) | cost |
|---|---|---|---|
| I | `m ≥ log q + 3s` | ~436 | extra communication round |
| **II** | **`m ≥ log q + 3s + 2λ_c`** | **692 → 696** | β available only late |
| III | `m ≥ log q + O(s·log m)` | ~1400 | ~4× bandwidth, ≥400 KB per signature |

**Variant II**, with `m = 696` (692 rounded up to a multiple of 8).

Rationale, recorded so it can be argued with:

- Variant III keeps DKLs' structure but needs roughly twice the OTs of Variant II and
  puts each signature above 400 KB. Asharov notes their analysis there is deliberately
  conservative — simple bounds, unoptimised constants — which is the right trade for a
  proof and the wrong one for a wire format we have to live with.
- Variant I is the smallest but adds a communication round to the VOLE.
- Variant II preserves the VOLE's round complexity by deriving `g` from a random oracle
  applied to the Sender's final message. Its cost is that the Receiver learns `β` late,
  which would add a round to signing — except that Asharov §6 modifies the two-round
  signing protocol so `β` is not needed early. **Implement that modified signing
  protocol, not the one in DKLs.**

---

## 5. Parameter summary

```
curve                secp256k1        (Mpc_secp256k1.Suite, CIPHERSUITE_CT)
log q                256
lambda_c             128
lambda_s             60
m   (OTs per VOLE)   696              = ceil(256 + 3*60 + 2*128) rounded to a multiple of 8
rho (masking)        1                NOT 2 as printed in DKLs
OT flavour           Sender-Random    NOT Endemic OT
VOLE variant         Asharov II       gadget vector g from RO over the Sender's last message
signing              Asharov section 6 two-round variant, not DKLs' as printed
```

Every one of these belongs in a test that fails if the constant changes without this
file changing with it.

---

## 6. What this pin does not cover

- **The OT extension is not chosen yet.** 696 OTs per VOLE is far past the point where
  base OTs alone are sensible, so an extension is required; Asharov notes base OTs stay
  on the order of λ_c and the rest come from symmetric-key work. The extension's own
  security analysis is a separate pin, and its interaction with the Sender-Random
  requirement in §3.2 must be checked, not assumed.
- **Nothing about implementation hazards**, which are tracked separately: Trail of Bits'
  review of an early DKLs library found channel nonce reuse, an abort handler that
  panicked instead of attributing blame, and a timing leak in PPRF evaluation. Those are
  D1 and D5 concerns.
- **Any revision after the dates in §1.** Both papers are live documents. The CGGMP21
  lesson is that a revision can be the difference between secure and not, so a stale pin
  is itself a risk. Re-read both before starting each milestone.
