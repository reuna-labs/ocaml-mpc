(** End-to-end FROST over the Ed25519 ciphersuite.

    The decisive check in this file is {!t_stock_verifier}: an aggregated FROST
    signature must be accepted by [Mirage_crypto_ec.Ed25519.verify], an entirely
    independent implementation of the verification equation that knows nothing
    about threshold signing. If the H2 domain separation, the challenge input,
    the group commitment or the scalar arithmetic were wrong, that check would
    fail. *)

open Testutil.Ed25519
module F = Mpc_frost.Core.Make (Mpc_ed25519.Suite)
module D = Mpc_frost.Dealer.Make (Mpc_ed25519.Suite)
module E = F.E

let subsets_of_size k xs =
  let rec go k xs =
    if k = 0 then [ [] ]
    else
      match xs with
      | [] -> []
      | x :: tl -> List.map (fun s -> x :: s) (go (k - 1) tl) @ go k tl
  in
  go k xs

(* One full signing round with the given signer subset. Returns the signature and the
   per-participant material, so tests can also poke at the intermediates. *)
let round ~seed ~msg ~(signers : D.key_package list) =
  let r = rand_of_seed seed in
  let commits =
    List.map
      (fun (kp : D.key_package) ->
        let nonces, c = Result.get_ok (F.commit r ~secret:kp.D.share) in
        (kp, nonces, c))
      signers
  in
  let cl =
    Result.get_ok
      (E.commitment_list (List.map (fun (kp, _, c) -> (kp.D.id, c)) commits))
  in
  let pk = (List.hd signers).D.group_public_key in
  let shares =
    List.map
      (fun ((kp : D.key_package), nonces, _) ->
        ( kp,
          Result.get_ok
            (F.sign ~id:kp.D.id ~share:kp.D.share ~group_public_key:pk ~nonces
               ~msg ~commitment_list:cl) ))
      commits
  in
  let bf = F.binding_factors ~group_public_key:pk ~commitment_list:cl ~msg in
  let gc = F.group_commitment ~commitment_list:cl ~binding_factors:bf in
  let sg = F.aggregate ~group_commitment:gc (List.map snd shares) in
  (sg, pk, cl, bf, shares)

let dealer_setup ~seed ~threshold ~n =
  let r = rand_of_seed seed in
  let secret = Result.get_ok (Sc.random r) in
  let packages, pkp =
    Result.get_ok (D.generate r ~secret ~threshold ~ids:(ids n))
  in
  (secret, packages, pkp)

let t_dealer_consistency () =
  let secret, packages, pkp = dealer_setup ~seed:"dealer" ~threshold:3 ~n:5 in
  Alcotest.check el "group key is secret*G" (El.scalar_mul_base secret) pkp.D.pk;
  List.iter
    (fun (kp : D.key_package) ->
      Alcotest.check el "verification share matches signing share"
        (El.scalar_mul_base kp.D.share)
        kp.D.verification_share;
      Alcotest.(check bool)
        "share verifies against the commitment" true
        (D.V.verify_share pkp.D.commitment
           { D.V.S.id = kp.D.id; value = kp.D.share }
        = Ok ()))
    packages

let t_sign_and_verify () =
  let _, packages, _ = dealer_setup ~seed:"sign" ~threshold:3 ~n:5 in
  let msg = "message to be signed by a threshold of parties" in
  List.iteri
    (fun i signers ->
      let sg, pk, _, _, _ =
        round ~seed:(Printf.sprintf "round%d" i) ~msg ~signers
      in
      Alcotest.(check bool)
        "signature verifies" true
        (F.verify ~group_public_key:pk ~msg sg);
      Alcotest.(check bool)
        "wrong message rejected" false
        (F.verify ~group_public_key:pk ~msg:(msg ^ "!") sg))
    (subsets_of_size 3 packages)

let t_stock_verifier () =
  let _, packages, _ = dealer_setup ~seed:"stock" ~threshold:2 ~n:3 in
  let msg = "verified by an implementation that has never heard of FROST" in
  List.iteri
    (fun i signers ->
      let sg, pk, _, _, _ =
        round ~seed:(Printf.sprintf "stock%d" i) ~msg ~signers
      in
      let ed_pub =
        Result.get_ok (Mirage_crypto_ec.Ed25519.pub_of_octets (El.serialize pk))
      in
      Alcotest.(check bool)
        "RFC 8032 verifier accepts the aggregated signature" true
        (Mirage_crypto_ec.Ed25519.verify ~key:ed_pub sg ~msg))
    (subsets_of_size 2 packages)

let t_share_attribution () =
  let _, packages, _ = dealer_setup ~seed:"attrib" ~threshold:3 ~n:5 in
  let msg = "identifiable abort" in
  let signers = List.filteri (fun i _ -> i < 3) packages in
  let _, pk, cl, bf, shares = round ~seed:"attrib-r" ~msg ~signers in
  (* Every honest share verifies. *)
  List.iter
    (fun ((kp : D.key_package), z) ->
      Alcotest.(check bool)
        "honest share verifies" true
        (F.verify_signature_share ~id:kp.D.id
           ~verification_share:kp.D.verification_share ~sig_share:z
           ~commitment_list:cl ~binding_factors:bf ~group_public_key:pk ~msg
        = Ok ()))
    shares;
  (* Corrupting exactly one share must be attributed to exactly that participant, and
     must break the aggregate -- otherwise identifiable abort is not identifying. *)
  List.iteri
    (fun victim _ ->
      let corrupted =
        List.mapi
          (fun i (kp, z) ->
            if i = victim then (kp, Sc.add z Sc.one) else (kp, z))
          shares
      in
      let gc = F.group_commitment ~commitment_list:cl ~binding_factors:bf in
      let sg = F.aggregate ~group_commitment:gc (List.map snd corrupted) in
      Alcotest.(check bool)
        "aggregate is invalid" false
        (F.verify ~group_public_key:pk ~msg sg);
      let culprits =
        List.filteri
          (fun _ _ -> true)
          (List.filter_map
             (fun ((kp : D.key_package), z) ->
               match
                 F.verify_signature_share ~id:kp.D.id
                   ~verification_share:kp.D.verification_share ~sig_share:z
                   ~commitment_list:cl ~binding_factors:bf ~group_public_key:pk
                   ~msg
               with
               | Ok () -> None
               | Error _ -> Some kp.D.id)
             corrupted)
      in
      Alcotest.(check int) "exactly one culprit" 1 (List.length culprits);
      Alcotest.check sc "the right culprit" (fst (List.nth shares victim)).D.id
        (List.hd culprits))
    shares

let t_commitment_list_validation () =
  let _, packages, _ = dealer_setup ~seed:"cl" ~threshold:2 ~n:3 in
  let r = rand_of_seed "cl-r" in
  let commit_of kp = snd (Result.get_ok (F.commit r ~secret:kp.D.share)) in
  let a = List.nth packages 0 and b = List.nth packages 1 in
  (* Bind each commitment once: [F.commit] draws fresh randomness on every call, so
     re-deriving one per use would compare different values, not different orderings. *)
  let ca = commit_of a and cb = commit_of b in
  Alcotest.(check bool)
    "duplicate identifier rejected" true
    (E.commitment_list [ (a.D.id, ca); (a.D.id, ca) ] = Error `Duplicate_id);
  Alcotest.(check bool)
    "zero identifier rejected" true
    (E.commitment_list [ (Sc.zero, ca) ] = Error `Zero_id);
  (* Order must not matter to the caller: the list is sorted before encoding, so two
     orderings produce byte-identical normative encodings and hence the same binding
     factors. Anything else makes signing order-dependent. *)
  let l1 = Result.get_ok (E.commitment_list [ (a.D.id, ca); (b.D.id, cb) ]) in
  let l2 = Result.get_ok (E.commitment_list [ (b.D.id, cb); (a.D.id, ca) ]) in
  Alcotest.(check string)
    "encoding is order-independent"
    (Ohex.encode (E.encode_commitment_list l1))
    (Ohex.encode (E.encode_commitment_list l2))

let suites =
  [
    ( "frost",
      [
        Alcotest.test_case "dealer consistency" `Quick t_dealer_consistency;
        Alcotest.test_case "sign and verify" `Quick t_sign_and_verify;
        Alcotest.test_case "stock RFC 8032 verifier" `Quick t_stock_verifier;
        Alcotest.test_case "share attribution" `Quick t_share_attribution;
        Alcotest.test_case "commitment list validation" `Quick
          t_commitment_list_validation;
      ] );
  ]
