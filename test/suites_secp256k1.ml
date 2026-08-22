(** The secp256k1 instantiation of every functorised suite.

    Adding this file, plus the ciphersuite it names, is what "adding a
    ciphersuite" costs: the arithmetic laws, the RFC known-answer tests and the
    end-to-end run are the same functors the Ed25519 suite is instantiated at.
*)

module Suite = Mpc_secp256k1.Suite

(* The independent judge for this ciphersuite.

   Unlike Ed25519 -- where a FROST signature is an ordinary RFC 8032 signature and
   mirage-crypto's Ed25519 can verify it -- there is no off-the-shelf verifier for a
   plain secp256k1 Schnorr signature in this shape: BIP-340 uses x-only keys and a
   different challenge. So the independent implementation used here is
   Mirage_crypto_blockchain.Secp256k1, which implements the same group in pure zarith
   and shares no code with the fiat-crypto/ECCKiila path the suite is built on. The
   verification equation is written out against it directly. *)
let verify_with_reference ~group_public_key ~msg sg =
  let module B = Mirage_crypto_blockchain.Secp256k1 in
  let ne = 33 and ns = 32 in
  if String.length sg <> ne + ns then false
  else
    match
      ( B.point_of_octets (String.sub sg 0 ne),
        B.scalar_of_octets (String.sub sg ne ns),
        B.point_of_octets group_public_key )
    with
    | Ok r, Ok z, Ok pk -> (
        (* c = H2(R || PK || msg), computed with the suite's own hash -- the point of the
         cross-check is the group arithmetic, not a second copy of the hash. *)
        let c = Suite.h2 (String.sub sg 0 ne ^ group_public_key ^ msg) in
        match B.scalar_of_octets (Suite.Scalar.serialize c) with
        | Error _ -> false
        | Ok c -> (
            (* z*G == R + c*PK *)
            match (B.scalar_mult z B.g, B.scalar_mult c pk) with
            | Ok lhs, Ok cpk -> (
                match B.add r cpk with
                | Ok rhs ->
                    String.equal
                      (B.point_to_octets ~compress:true lhs)
                      (B.point_to_octets ~compress:true rhs)
                | Error _ -> false)
            | _ -> false))
    | _ -> false

module Arith =
  Suite_arith.Make
    (Suite)
    (struct
      let name = "arith-secp256k1"
    end)

module Vectors =
  Suite_vectors.Make
    (Suite)
    (struct
      let name = "rfc9591-secp256k1"
      let file = "vectors/frost-secp256k1-sha256.json"
      let verify_with_reference = verify_with_reference
    end)

module E2e =
  Suite_e2e.Make
    (Suite)
    (struct
      let name = "e2e-secp256k1"
      let verify_with_reference = verify_with_reference
    end)

let suites = Arith.suites @ Vectors.suites @ E2e.suites
