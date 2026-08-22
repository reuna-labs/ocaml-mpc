(** Shamir secret sharing and Feldman VSS. *)

open Testutil.Ed25519
module Sh = Mpc.Shamir.Make (Mpc_ed25519.Suite)
module V = Mpc.Vss.Make (Mpc_ed25519.Suite)

let subsets_of_size k xs =
  let rec go k xs =
    if k = 0 then [ [] ]
    else
      match xs with
      | [] -> []
      | x :: tl -> List.map (fun s -> x :: s) (go (k - 1) tl) @ go k tl
  in
  go k xs

let t_split_reconstruct () =
  let r = rand_of_seed "split" in
  for n = 1 to 6 do
    for t = 1 to n do
      let secret = Result.get_ok (Sc.random r) in
      let ids = ids n in
      let shares, poly = Result.get_ok (Sh.split r ~secret ~threshold:t ~ids) in
      Alcotest.(check int) "share count" n (List.length shares);
      Alcotest.check sc "a_0 is the secret" secret (Sh.secret poly);
      (* Every t-subset reconstructs; the shares are indistinguishable. *)
      List.iter
        (fun sub ->
          Alcotest.check sc
            (Printf.sprintf "t=%d n=%d subset reconstructs" t n)
            secret
            (Result.get_ok (Sh.interpolate_secret sub)))
        (subsets_of_size t shares);
      Sh.wipe poly
    done
  done

let t_below_threshold_differs () =
  (* t-1 shares must not reconstruct the secret. This is not a proof of secrecy -- it
     cannot be, in a test -- but a regression guard: an off-by-one in the polynomial
     degree would make t-1 shares suffice, and that would silently pass every other
     test in this file. *)
  let r = rand_of_seed "below" in
  let secret = Result.get_ok (Sc.random r) in
  let ids = ids 5 in
  let shares, poly = Result.get_ok (Sh.split r ~secret ~threshold:3 ~ids) in
  Sh.wipe poly;
  List.iter
    (fun sub ->
      Alcotest.(check bool)
        "t-1 shares do not reconstruct" false
        (Sc.equal secret (Result.get_ok (Sh.interpolate_secret sub))))
    (subsets_of_size 2 shares)

let t_id_validation () =
  let r = rand_of_seed "ids" in
  let secret = Result.get_ok (Sc.random r) in
  let ok = ids 3 in
  Alcotest.(check bool)
    "threshold 0 rejected" true
    (Result.is_error (Sh.split r ~secret ~threshold:0 ~ids:ok));
  Alcotest.(check bool)
    "threshold > n rejected" true
    (Result.is_error (Sh.split r ~secret ~threshold:4 ~ids:ok));
  Alcotest.(check bool)
    "duplicate id rejected" true
    (Sh.split r ~secret ~threshold:2 ~ids:[ id 1; id 1; id 2 ]
    |> Result.map (fun _ -> ())
    |> ( = ) (Error `Duplicate_id));
  Alcotest.(check bool)
    "zero id rejected" true
    (Sh.split r ~secret ~threshold:2 ~ids:[ Sc.zero; id 2 ]
    |> Result.map (fun _ -> ())
    |> ( = ) (Error `Zero_id))

let t_lagrange_batch_agrees () =
  let ids = ids 5 in
  let all = Result.get_ok (Sh.lagrange_all ~ids) in
  List.iter2
    (fun i l ->
      Alcotest.check sc "batch = single"
        (Result.get_ok (Sh.lagrange ~ids ~id:i))
        l)
    ids all;
  (* The interpolating values of any set sum to 1: sum_i lambda_i = f(0) for f = 1. *)
  Alcotest.check sc "coefficients sum to one" Sc.one
    (List.fold_left Sc.add Sc.zero all);
  Alcotest.(check bool)
    "non-participant rejected" true
    (Sh.lagrange ~ids ~id:(id 99) = Error `Not_a_participant)

let t_vss_verify () =
  let r = rand_of_seed "vss" in
  let secret = Result.get_ok (Sc.random r) in
  let ids = ids 5 in
  let shares, poly = Result.get_ok (Sh.split r ~secret ~threshold:3 ~ids) in
  let c = V.commit poly in
  Sh.wipe poly;
  Alcotest.check el "phi_0 = secret * G"
    (El.scalar_mul_base secret)
    (V.secret_commitment c);
  List.iter
    (fun sh ->
      Alcotest.(check bool)
        "honest share verifies" true
        (V.verify_share c sh = Ok ()))
    shares;
  (* Every corruption of a share value must be caught. *)
  List.iter
    (fun (sh : Sh.share) ->
      let bad = { sh with Sh.value = Sc.add sh.Sh.value Sc.one } in
      Alcotest.(check bool)
        "corrupted share rejected" true
        (V.verify_share c bad = Error `Bad_share);
      let wrong_id = { sh with Sh.id = id 42 } in
      Alcotest.(check bool)
        "share under the wrong id rejected" true
        (V.verify_share c wrong_id = Error `Bad_share))
    shares

let t_vss_combine () =
  (* The DKG's joint polynomial: summing commitments must agree with summing shares. *)
  let r = rand_of_seed "combine" in
  let ids = ids 4 in
  let parties =
    List.map
      (fun _ ->
        let secret = Result.get_ok (Sc.random r) in
        let shares, poly =
          Result.get_ok (Sh.split r ~secret ~threshold:3 ~ids)
        in
        let c = V.commit poly in
        Sh.wipe poly;
        (secret, shares, c))
      ids
  in
  let commitments = List.map (fun (_, _, c) -> c) parties in
  let joint = Result.get_ok (V.combine commitments) in
  let expected_pk =
    List.fold_left
      (fun acc (s, _, _) -> El.add acc (El.scalar_mul_base s))
      El.identity parties
  in
  Alcotest.check el "group key is the sum of the secret commitments" expected_pk
    (V.secret_commitment joint);
  (* Each party's signing share is the sum of the shares it received. *)
  List.iteri
    (fun i my_id ->
      let s_i =
        List.fold_left
          (fun acc (_, shares, _) -> Sc.add acc (List.nth shares i).Sh.value)
          Sc.zero parties
      in
      Alcotest.check el "verification share from combined commitments"
        (El.scalar_mul_base s_i)
        (Result.get_ok (V.participant_public_key commitments ~id:my_id)))
    ids;
  Alcotest.(check bool)
    "length mismatch rejected" true
    (Result.is_error
       (V.combine [ Array.make 2 El.identity; Array.make 3 El.identity ]))

let t_vss_codec () =
  let r = rand_of_seed "vsscodec" in
  let secret = Result.get_ok (Sc.random r) in
  let _, poly = Result.get_ok (Sh.split r ~secret ~threshold:3 ~ids:(ids 3)) in
  let c = V.commit poly in
  Sh.wipe poly;
  let s = V.serialize c in
  Alcotest.(check int) "length" (3 * 32) (String.length s);
  let c' = Result.get_ok (V.deserialize ~threshold:3 s) in
  Array.iteri (fun i p -> Alcotest.check el "round trip" p c'.(i)) c;
  Alcotest.(check bool)
    "wrong threshold rejected" true
    (Result.is_error (V.deserialize ~threshold:2 s))

let t_wipe_erases () =
  (* The claim is that wiping a polynomial overwrites bytes rather than dropping a
     reference. Asserted, not assumed -- and a use-after-wipe must be loud, because the
     alternative is signing with zeroed key material. *)
  let r = rand_of_seed "wipe" in
  let secret = Result.get_ok (Sc.random r) in
  let _, poly = Result.get_ok (Sh.split r ~secret ~threshold:3 ~ids:(ids 5)) in
  Alcotest.check sc "the secret is readable before wiping" secret
    (Sh.secret poly);
  Sh.wipe poly;
  List.iter
    (fun (name, f) ->
      Alcotest.check_raises name
        (Invalid_argument
           (Printf.sprintf "Mpc.Shamir.%s: the polynomial has been wiped" name))
        f)
    [
      ("secret", fun () -> ignore (Sh.secret poly));
      ("coeff", fun () -> ignore (Sh.coeff poly 0));
      ("coefficients", fun () -> ignore (Sh.coefficients poly));
      ("eval", fun () -> ignore (Sh.eval poly (id 1)));
    ];
  (* Wiping twice is not an error. *)
  Sh.wipe poly

let suites =
  [
    ( "shamir",
      [
        Alcotest.test_case "split and reconstruct" `Quick t_split_reconstruct;
        Alcotest.test_case "below threshold" `Quick t_below_threshold_differs;
        Alcotest.test_case "identifier validation" `Quick t_id_validation;
        Alcotest.test_case "lagrange" `Quick t_lagrange_batch_agrees;
        Alcotest.test_case "wipe erases and is final" `Quick t_wipe_erases;
      ] );
    ( "vss",
      [
        Alcotest.test_case "share verification" `Quick t_vss_verify;
        Alcotest.test_case "combine" `Quick t_vss_combine;
        Alcotest.test_case "serialization" `Quick t_vss_codec;
      ] );
  ]
