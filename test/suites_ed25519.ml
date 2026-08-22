(** The Ed25519 instantiation of every functorised suite.

    Adding a ciphersuite means adding a file like this one, not another copy of
    the tests. *)

module Suite = Mpc_ed25519.Suite

(* The independent judge for this ciphersuite. A FROST(Ed25519, SHA-512) signature is an
   ordinary RFC 8032 signature, so mirage-crypto's Ed25519 -- which knows nothing about
   threshold signing -- can verify it. *)
let verify_with_reference ~group_public_key ~msg sg =
  match Mirage_crypto_ec.Ed25519.pub_of_octets group_public_key with
  | Ok key -> Mirage_crypto_ec.Ed25519.verify ~key sg ~msg
  | Error _ -> false

module Vectors =
  Suite_vectors.Make
    (Suite)
    (struct
      let name = "rfc9591-ed25519"
      let file = "vectors/frost-ed25519-sha512.json"
      let verify_with_reference = verify_with_reference
    end)

module Arith =
  Suite_arith.Make
    (Suite)
    (struct
      let name = "arith-ed25519"
    end)

module E2e =
  Suite_e2e.Make
    (Suite)
    (struct
      let name = "e2e-ed25519"
      let verify_with_reference = verify_with_reference
    end)

let suites = Arith.suites @ Vectors.suites @ E2e.suites
