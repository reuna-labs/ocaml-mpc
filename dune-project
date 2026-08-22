(lang dune 3.6)

(name mpc)

(generate_opam_files true)

(implicit_transitive_deps false)

(source
 (github reuna-labs/ocaml-mpc))

(license ISC)

(authors "Gil Bahat <bahat.gil@gmail.com>")

(maintainers "Gil Bahat <bahat.gil@gmail.com>")

(documentation "https://reuna-labs.github.io/ocaml-mpc/")

(package
 (name mpc)
 (synopsis "Threshold signatures and multi-party computation, free of I/O")
 (description
  "A multi-party computation library for OCaml. The first protocol is FROST,\nthe two-round threshold Schnorr signature scheme of RFC 9591: distributed key\ngeneration by trusted dealer or by the two-round Pedersen DKG, two-round\nsigning, signature-share verification with identifiable abort, and Shamir\nsecret sharing with Feldman verifiable secret sharing over an abstract\nprime-order group.\n\nThe protocol core is a pure state machine: no I/O, no scheduler, no clock and\nno ambient randomness. Time enters only as a timeout input the driver chooses\nto inject and randomness only as a function the caller supplies, so the same\ncode drives a Unix process, a MirageOS/Solo5 unikernel, and a fully\ndeterministic in-memory simulator that replays an entire n-party run,\nadversarial message schedule included, from a single 32-byte seed.\n\nThe FROST(Ed25519, SHA-512) ciphersuite depends on mirage-crypto-ec alone --\nno zarith, hence no GMP -- and its signatures are ordinary RFC 8032 Ed25519\nsignatures, verifiable by any standard verifier.")
 (tags
  ("mpc" "threshold-signatures" "tss" "frost" "schnorr" "ed25519" "org:mirage"))
 (depends
  (ocaml
   (>= 4.14.0))
  (dune
   (>= 3.6))
  (digestif
   (>= 1.2.0))
  (eqaf
   (>= 0.9))
  (mirage-crypto-ec
   (>= 2.1.0))
  (mirage-crypto-rng
   (and
    :with-test
    (>= 2.1.0)))
  (alcotest :with-test)
  (qcheck-core :with-test)
  (qcheck-alcotest :with-test)
  (ohex
   (and
    :with-test
    (>= 0.2.0)))
  (yojson
   (and
    :with-test
    (>= 2.0.0)))))

(package
 (name mpc-lwt)
 (synopsis "Lwt transport for ocaml-mpc, functorised over Mirage_flow.S")
 (description
  "The transport layer for ocaml-mpc: length-prefixed framing, a flow-generic\ntransport, and a driver that owns the clock and turns the sans-IO protocol core\ninto a running participant.\n\nFunctorised over Mirage_flow.S rather than bound to a socket API, so the same\ncode runs over TCP, over vsock, or over TLS inside a MirageOS/Solo5 unikernel.\nIt does not depend on unix; mpc-unix does that, and only that.\n\nLwt rather than Eio is a constraint, not a preference: MirageOS has no Eio\nbackend, so a unikernel-capable transport has to be Lwt-based.")
 (tags ("mpc" "threshold-signatures" "frost" "mirage" "org:mirage"))
 (depends
  (ocaml
   (>= 4.14.0))
  (dune
   (>= 3.6))
  (mpc
   (= :version))
  (lwt
   (>= 5.6.0))
  (cstruct
   (>= 6.0.0))
  (mirage-flow
   (>= 4.0.0))
  (mirage-crypto
   (>= 2.1.0))
  logs
  fmt
  (alcotest :with-test)))

(package
 (name mpc-unix)
 (synopsis "Unix sockets for ocaml-mpc")
 (description
  "A Mirage_flow.S over Lwt_unix sockets, plus address parsing and an accept\nloop, so a FROST participant can be run as an ordinary Unix process.\n\nThis is the only package in the repository permitted to depend on unix. Keeping\nit separate is what lets the protocol core and the transport cross-compile to a\nSolo5 unikernel unchanged.")
 (tags ("mpc" "threshold-signatures" "frost" "org:mirage"))
 (depends
  (ocaml
   (>= 4.14.0))
  (dune
   (>= 3.6))
  (mpc-lwt
   (= :version))
  (lwt
   (>= 5.6.0))
  (cstruct
   (>= 6.0.0))
  (mirage-flow
   (>= 4.0.0))
  (mirage-flow-unix
   (>= 4.0.0))
  logs
  (alcotest :with-test)))
