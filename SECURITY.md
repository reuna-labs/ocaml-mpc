# Security policy

This repository is unaudited alpha cryptographic software. Do not use it for
valuable key shares. Report vulnerabilities privately to `security@reuna.io`
and do not open a public issue before a coordinated fix is available.

## Review boundary

The priority surfaces are DKG participant authentication, nonce generation and
single use, transcript/session binding, duplicate or equivocated messages,
share verification, identifiable abort, serialization and the distinction
between FROST Schnorr signatures and ordinary ECDSA.

The core deliberately receives randomness and transport as capabilities. The
caller must provide a healthy entropy source, authenticated confidential
channels, durable anti-replay state and secure share lifecycle. OCaml heap
values are not reliably zeroized; enclave isolation does not replace protocol
review or operational share-recovery planning.
