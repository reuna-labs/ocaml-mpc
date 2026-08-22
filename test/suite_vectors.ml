(** RFC 9591 known-answer tests, over any ciphersuite with published vectors.

    This is the highest-value test in the suite. Reproducing only the final
    signature would say "something is wrong" on a mismatch; reproducing every
    intermediate says {e which} thing. The binding-factor input isolates the
    normative commitment-list encoding, H4 and H5; the binding factor isolates
    H1; each signature share isolates the Lagrange coefficient and the scalar
    arithmetic. *)

module Make
    (C : Mpc.Group.CIPHERSUITE)
    (V : sig
      val name : string
      val file : string

      val verify_with_reference :
        group_public_key:string -> msg:string -> string -> bool
      (** An independent verifier for this ciphersuite, so an accepted signature
          is judged by something other than the code that produced it. *)
    end) =
struct
  include Testutil.Make (C)
  module F = Mpc_frost.Core.Make (C)
  module D = Mpc_frost.Dealer.Make (C)
  module E = F.E

  let json =
    lazy
      (try Yojson.Safe.from_file V.file
       with _ -> Alcotest.failf "cannot read %s" V.file)

  let mem k j =
    match j with
    | `Assoc l -> List.assoc k l
    | _ -> Alcotest.failf "not an object"

  let str j = match j with `String s -> s | _ -> Alcotest.failf "not a string"
  let int_ j = match j with `Int i -> i | _ -> Alcotest.failf "not an int"
  let list_ j = match j with `List l -> l | _ -> Alcotest.failf "not a list"
  let hexf j k = Ohex.decode (str (mem k j))

  let scalar_of h =
    match Sc.deserialize h with
    | Ok s -> s
    | Error _ -> Alcotest.failf "vector scalar is not a valid group scalar"

  let element_of h =
    match El.deserialize h with
    | Ok e -> e
    | Error _ -> Alcotest.failf "vector element is not a valid group element"

  (* A randomness source that hands out fixed values in order: the vector fixes the nonce
     randomness, so reproducing its nonces means feeding exactly those bytes. *)
  let fixed_rand values =
    let remaining = ref values in
    Mpc.Rand.v (fun n ->
        match !remaining with
        | v :: tl when String.length v = n ->
            remaining := tl;
            v
        | _ -> Alcotest.failf "fixed_rand: unexpected request for %d bytes" n)

  type participant = {
    ident : Sc.t;
    share : Sc.t;
    hiding : Sc.t;
    binding : Sc.t;
    commitment : E.commitment;
    bf_input : string;
    bf : Sc.t;
    sig_share : Sc.t;
  }

  let load () =
    let j = Lazy.force json in
    let inputs = mem "inputs" j in
    let group_secret = scalar_of (hexf inputs "group_secret_key") in
    let group_pk = element_of (hexf inputs "group_public_key") in
    let msg = str (mem "message" inputs) |> Ohex.decode in
    let coeffs =
      List.map
        (fun c -> scalar_of (Ohex.decode (str c)))
        (list_ (mem "share_polynomial_coefficients" inputs))
    in
    let dealer_shares =
      List.map
        (fun o ->
          (int_ (mem "identifier" o), scalar_of (hexf o "participant_share")))
        (list_ (mem "participant_shares" inputs))
    in
    let r1 = list_ (mem "outputs" (mem "round_one_outputs" j)) in
    let r2 = list_ (mem "outputs" (mem "round_two_outputs" j)) in
    let sig_share_of i =
      List.find_map
        (fun o ->
          if int_ (mem "identifier" o) = i then
            Some (scalar_of (hexf o "sig_share"))
          else None)
        r2
      |> Option.get
    in
    let participants =
      List.map
        (fun o ->
          let i = int_ (mem "identifier" o) in
          {
            ident = id i;
            share = List.assoc i dealer_shares;
            hiding = scalar_of (hexf o "hiding_nonce");
            binding = scalar_of (hexf o "binding_nonce");
            commitment =
              {
                E.hiding = element_of (hexf o "hiding_nonce_commitment");
                binding = element_of (hexf o "binding_nonce_commitment");
              };
            bf_input = hexf o "binding_factor_input";
            bf = scalar_of (hexf o "binding_factor");
            sig_share = sig_share_of i;
          })
        r1
    in
    let randomness =
      List.concat_map
        (fun o ->
          [
            hexf o "hiding_nonce_randomness"; hexf o "binding_nonce_randomness";
          ])
        r1
    in
    let expected_sig = hexf (mem "final_output" j) "sig" in
    ( group_secret,
      group_pk,
      msg,
      coeffs,
      dealer_shares,
      participants,
      randomness,
      expected_sig )

  (* 1. The dealer reproduces the published shares and the group public key. *)
  let t_dealer () =
    let group_secret, group_pk, _, coeffs, dealer_shares, _, _, _ = load () in
    let coefficients = Array.of_list (group_secret :: coeffs) in
    let n = List.length dealer_shares in
    let packages, pkp =
      Result.get_ok (D.of_coefficients ~coefficients ~ids:(ids n))
    in
    Alcotest.check el "group public key" group_pk pkp.D.pk;
    List.iter
      (fun (kp : D.key_package) ->
        let i =
          List.find (fun (i, _) -> Sc.equal (id i) kp.D.id) dealer_shares |> fst
        in
        Alcotest.check sc
          (Printf.sprintf "participant %d share" i)
          (List.assoc i dealer_shares)
          kp.D.share)
      packages

  (* 2. nonce_generate reproduces the published nonces and commitments. *)
  let t_nonces () =
    let _, _, _, _, _, participants, randomness, _ = load () in
    let rand = fixed_rand randomness in
    List.iter
      (fun p ->
        let nonces, commitment =
          Result.get_ok (F.commit rand ~secret:p.share)
        in
        Alcotest.check sc "hiding nonce" p.hiding nonces.F.hiding;
        Alcotest.check sc "binding nonce" p.binding nonces.F.binding;
        Alcotest.check el "hiding commitment" p.commitment.E.hiding
          commitment.E.hiding;
        Alcotest.check el "binding commitment" p.commitment.E.binding
          commitment.E.binding)
      participants

  (* 3. The binding-factor input reproduces byte for byte. This is the check that
        localises a fault to the normative commitment-list encoding, H4 or H5. *)
  let t_binding_factor_input () =
    let _, group_pk, msg, _, _, participants, _, _ = load () in
    let cl =
      Result.get_ok
        (E.commitment_list
           (List.map (fun p -> (p.ident, p.commitment)) participants))
    in
    List.iter
      (fun p ->
        let got =
          E.binding_factor_input ~group_public_key:group_pk ~commitment_list:cl
            ~msg p.ident
        in
        Alcotest.(check string)
          "binding factor input" (Ohex.encode p.bf_input) (Ohex.encode got))
      participants

  (* 4. The binding factors themselves, which isolates H1. *)
  let t_binding_factors () =
    let _, group_pk, msg, _, _, participants, _, _ = load () in
    let cl =
      Result.get_ok
        (E.commitment_list
           (List.map (fun p -> (p.ident, p.commitment)) participants))
    in
    let bf =
      F.binding_factors ~group_public_key:group_pk ~commitment_list:cl ~msg
    in
    List.iter
      (fun p ->
        let got = List.find (fun (i, _) -> Sc.equal i p.ident) bf |> snd in
        Alcotest.check sc "binding factor" p.bf got)
      participants

  (* 5. Each signature share, which isolates the Lagrange coefficient and the scalar
        arithmetic; then the aggregate, byte for byte. *)
  let t_shares_and_signature () =
    let _, group_pk, msg, _, _, participants, _, expected_sig = load () in
    let cl =
      Result.get_ok
        (E.commitment_list
           (List.map (fun p -> (p.ident, p.commitment)) participants))
    in
    let bf =
      F.binding_factors ~group_public_key:group_pk ~commitment_list:cl ~msg
    in
    let gc = F.group_commitment ~commitment_list:cl ~binding_factors:bf in
    List.iter
      (fun p ->
        let z =
          Result.get_ok
            (F.sign ~id:p.ident ~share:p.share ~group_public_key:group_pk
               ~nonces:{ F.hiding = p.hiding; binding = p.binding }
               ~msg ~commitment_list:cl)
        in
        Alcotest.check sc "signature share" p.sig_share z;
        (* And the published share must pass our own verification check. *)
        Alcotest.(check bool)
          "published share verifies" true
          (F.verify_signature_share ~id:p.ident
             ~verification_share:(El.scalar_mul_base p.share)
             ~sig_share:p.sig_share ~commitment_list:cl ~binding_factors:bf
             ~group_public_key:group_pk ~msg
          = Ok ()))
      participants;
    let sg =
      F.aggregate ~group_commitment:gc
        (List.map (fun p -> p.sig_share) participants)
    in
    Alcotest.(check string)
      "final signature" (Ohex.encode expected_sig) (Ohex.encode sg);
    Alcotest.(check bool)
      "and it verifies" true
      (F.verify ~group_public_key:group_pk ~msg sg);
    Alcotest.(check bool)
      "and an independent verifier accepts it" true
      (V.verify_with_reference ~group_public_key:(El.serialize group_pk) ~msg sg)

  let suites =
    [
      ( V.name,
        [
          Alcotest.test_case "trusted dealer" `Quick t_dealer;
          Alcotest.test_case "nonces and commitments" `Quick t_nonces;
          Alcotest.test_case "binding factor input" `Quick
            t_binding_factor_input;
          Alcotest.test_case "binding factors" `Quick t_binding_factors;
          Alcotest.test_case "signature shares and aggregate" `Quick
            t_shares_and_signature;
        ] );
    ]
end
