# Timing measurements

A dudect-style detector for input-dependent timing in the operations FROST applies to
secret scalars.

```
dune exec test/timing/timing_ct.exe
```

It is deliberately **not** part of `dune runtest`: it takes minutes, and on a
general-purpose machine it is noisy enough that a spurious failure would train people
to ignore it.

## What a result means

It can find leakage. It cannot prove absence. A clean result means this setup, on this
machine, for these inputs, did not detect a difference — evidence, not proof, and much
weaker than a verified implementation or an instrumented run under valgrind.

The constant-time claim in the main README rests on an *argument* — that FROST applies
arbitrary-point scalar multiplication only to public scalars, and that the two
secret-dependent operations are constant time in the underlying C — plus the
`Element.scalar_mul` allowlist lint that keeps the argument true as the code changes.
This adds measurement to that. It does not replace it.

## Why there is a positive control

A detector that reports "no leakage" without ever having been shown to detect leakage
is worthless: an instrument too blunt to see anything reports success on everything. So
the run includes `Element.scalar_mul`, which is documented as variable time. If that is
*not* flagged, the whole run reports INCONCLUSIVE rather than passing.

## Four things this harness got wrong, and what fixed them

Recorded because each one produced a confident, wrong answer, and because anyone
tempted to loosen these should know what they are undoing.

1. **A single t-value is not a result.** The first version reported |t| = 10.0 for
   `Scalar.muladd` and 9.3 for `Scalar.mul` in the same run — the same underlying
   operation, one either side of the threshold. That is a busy laptop, not a finding.
   Fixed by taking the **median over independent rounds**: noise averages out, a real
   difference does not.

2. **Class order inside a sample must be randomised.** Timing the fixed class first
   every time makes any order effect — a cold branch predictor, a cache line the first
   loop warms for the second — look like a class difference, and it does *not* average
   out across rounds. It hits the cheapest operation hardest, where a constant per-loop
   overhead is proportionally largest. The symptom was `Eqaf.equal`, a purpose-built
   constant-time comparison, holding at |t| = 18 across five rounds while every
   arithmetic operation sat below 2. Fixed by a coin flip per sample.

3. **The fixed input has to be chosen deliberately.** Using an all-zero fixed class
   made `Scalar.invert` report |t| = 234 — which was real, and was the early return on
   a zero input rather than anything about the exponentiation chain. That early return
   is gone now, and inversion is measured against both a zero and a fixed non-zero
   class, because the two ask different questions.

4. **The two classes must differ in their value and nothing else.** Reusing one
   constant as the fixed input leaves it permanently in L1, while the random input is a
   fresh allocation paying a cold miss once per sample. That is a property of the
   harness, and it scales inversely with the cost of the operation: one cache miss is a
   large fraction of a small measurement window and negligible in a large one. The
   symptom was `Eqaf.equal` — the cheapest operation measured, and a purpose-built
   constant-time comparison — flagged at |t| = 10.5 against a floor of 1.2, while
   `Element.scalar_mul_base`, four orders of magnitude more work per call, sat at 0.25.
   Copying the fixed value into a fresh string each sample took `Eqaf.equal` to 1.05.

## Reading a clean run

A representative clean result:

```
positive control (Element.scalar_mul (known variable time)):
                                     |t| = 1613.48  (noise floor  10.76)  LEAK DETECTED
  Scalar.muladd  (secret, hot path)  |t| =    4.54  (noise floor   0.56)  not rejected
  Scalar.mul                         |t| =    5.92  (noise floor   2.52)  not rejected
  Scalar.add                         |t| =    4.07  (noise floor   0.60)  not rejected
  Scalar.invert vs zero              |t| =    8.76  (noise floor   0.42)  not rejected
  Scalar.invert vs fixed non-zero    |t| =    8.73  (noise floor   0.53)  not rejected
  Element.scalar_mul_base (secret)   |t| =    1.90  (noise floor   0.68)  not rejected
  Scalar.equal (Eqaf)                |t| =    1.05  (noise floor   0.66)  not rejected
```

Read the ratio, not just the verdict. Both inversion rows sit near |t| = 8.7 against a
floor around 0.5 — under the absolute threshold, so not flagged, but roughly seventeen
times their own noise floor, which is the highest ratio of anything that passed. Two
things are worth knowing about that:

- `Scalar.invert` is applied only to {b public} values in this library — Lagrange
  denominators, derived from participant identifiers. Even a real difference there is
  not on a secret path. The `Element.scalar_mul` allowlist and the argument in the main
  README are what establish that, not this measurement.
- The fixed classes for inversion are degenerate by design (zero, and one), so their
  exponentiation chains carry degenerate intermediates throughout while a random
  scalar's do not. Whether that is a property of `sc_muladd` or another artefact of
  measuring a batch is not established here. It is on the list, not dismissed.

The flagging rule is a conjunction — above the absolute threshold {b and} above three
times the floor — which is deliberately conservative: it prefers a missed detection to
a false one, because a harness that cries wolf gets switched off.

## What is not covered

- Measurements are of a *batch* of repetitions, because a single scalar multiplication
  is far below the resolution of any clock reachable from OCaml. That detects gross
  leakage — a data-dependent early exit, a variable-length loop — not a single-cycle
  difference.
- `ctgrind` (marking secrets undefined under valgrind, so any branch or index on them is
  reported) is the stronger tool and is not used here: valgrind is not usable on this
  platform. It belongs in CI on a Linux runner.
