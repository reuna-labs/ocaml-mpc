# Test vectors

Every file here is recorded with its upstream source, the revision it was taken from,
and its licence, per the convention in `CONTRIBUTING.md`.

## `frost-ed25519-sha512.json` and `frost-secp256k1-sha256.json`

- **Contents:** the FROST(Ed25519, SHA-512) known-answer vector — trusted-dealer key
  material, per-participant nonces and commitments, binding-factor inputs and binding
  factors, signature shares, and the final signature.
- **Upstream:** RFC 9591, *The Flexible Round-Optimized Schnorr Threshold (FROST)
  Protocol for Two-Round Schnorr Signatures*, Appendices **E.1** (Ed25519) and **E.5**
  (secp256k1). <https://www.rfc-editor.org/rfc/rfc9591.txt>
- **Revision:** RFC 9591, published June 2024 (the RFC text is immutable).
- **Licence:** RFC text is published under the IETF Trust's Legal Provisions
  (BCP 78 / RFC 5378); the code components in it are licensed under the Revised BSD
  License. Test vectors are code components.
- **Transcription:** reformatted from the RFC's key/value listing into JSON, by a
  parser that rejoins the RFC's line-wrapped hex. Field names follow the RFC's own
  labels so a reader can diff them against the appendix directly. No value was altered,
  abbreviated, or re-derived. The Ed25519 file was originally transcribed by hand and
  was later re-derived by that parser and confirmed identical, field for field.
- **Why every intermediate is kept, not just the signature:** a mismatch in the final
  signature alone says only "something is wrong". Checking the binding-factor input
  byte-for-byte localises a fault to the normative commitment-list encoding, H4 or H5;
  checking the binding factor isolates H1; checking each signature share isolates the
  Lagrange coefficient and the scalar arithmetic. That is the difference between a
  failing test and a diagnosable one.

### A third-party copy that is *not* a substitute

`ZcashFoundation/frost` ships `frost-*/tests/helpers/vectors.json`, which looks like the
same thing and is not. Its key material matches RFC 9591 exactly — group secret, group
public key, polynomial coefficients, every participant share — but its **round-one
nonces, binding factors and final signature differ**, so it appears to be a draft-era
vector set rather than the published one.

That was caught by diffing their Ed25519 file against this one before trusting it, and
it is the reason these files come from the RFC text and nowhere else. Cross-checking
against their *implementation* is still worth doing and is what `test/interop/` is for;
cross-checking against their *vectors* would have quietly validated the wrong answers.

### What is deliberately absent

RFC 9591 publishes **no test vectors for the two-round DKG of Appendix D**, and does
not fix that protocol's proof-of-knowledge challenge hash. The DKG in this library is
therefore self-consistent and covered by round-trip and fault-injection tests, but is
**not** verified against any external implementation. Cross-validating it against
`ZcashFoundation/frost` is tracked as follow-up work; see `CONTRIBUTING.md`.

## `rfc9380-expand-message-xmd-sha256.json`

- **Contents:** the `expand_message_xmd(SHA-256)` known-answer vectors — both the
  ordinary-DST and long-DST blocks, twenty cases in total, covering messages from empty
  to 517 bytes and outputs of 32 and 128 bytes.
- **Upstream:** RFC 9380, *Hashing to Elliptic Curves*, Appendices K.1 and K.2.
  <https://www.rfc-editor.org/rfc/rfc9380.txt>
- **Licence:** as above — IETF Trust Legal Provisions; code components under the Revised
  BSD License.
- **Why separately from the FROST vectors:** the secp256k1 ciphersuite reaches its
  scalar field through `hash_to_field`, which is built on this expander. Testing the
  expander on its own means a later mismatch in a FROST binding factor points at the
  protocol rather than being ambiguous between the two. The long-DST block earns its
  place in particular: a DST over 255 bytes must be hashed down first, and an
  implementation that skips that produces plausible output that agrees with nobody.
