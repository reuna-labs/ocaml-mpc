(* Our half of the cross-implementation check against ZcashFoundation/frost.

   The RFC 9591 vectors already prove we agree with the specification. What they cannot
   prove is that we agree with another implementation on everything the specification
   leaves to be inferred -- identifier encoding, the exact bytes hashed, point and
   scalar serialisation. Two directions are checked, so neither side is merely trusted:

     their signature -> our verifier
     their key material -> our signing -> their verifier

   The second is the stronger one. It uses shares this code did not produce, runs them
   through our round 1, round 2 and aggregation, and hands the result to a verifier
   that has never seen our code. *)

let die fmt =
  Printf.ksprintf
    (fun s ->
      prerr_endline ("interop: " ^ s);
      exit 1)
    fmt

let mem k j =
  match j with `Assoc l -> List.assoc k l | _ -> die "not an object"

let str j = match j with `String s -> s | _ -> die "not a string"
let hexf j k = Ohex.decode (str (mem k j))

module Make
    (Suite : Mpc.Group.CIPHERSUITE)
    (R : sig
      val reference :
        (string * (group_public_key:string -> msg:string -> string -> bool))
        option
      (** A second, independent verifier for this ciphersuite, with a name for
          the output.

          [None] where there is no meaningful one. A FROST(Ed25519) signature is
          an ordinary RFC 8032 signature, so any Ed25519 verifier judges it; a
          secp256k1 Schnorr signature in this shape has no off-the-shelf
          verifier, because BIP-340 uses x-only keys and a different challenge.
          Direction 2 is the real cross-check either way. *)
    end) =
struct
  module Sc = Suite.Scalar
  module El = Suite.Element
  module F = Mpc_frost.Core.Make (Suite)
  module E = F.E

  let scalar_of ctx h =
    match Sc.deserialize h with
    | Ok s -> s
    | Error _ -> die "%s: not a valid scalar" ctx

  let element_of ctx h =
    match El.deserialize h with
    | Ok e -> e
    | Error _ -> die "%s: not a valid element" ctx

  (* their signature -> our verifier *)
  let verify_theirs file =
    let j = Yojson.Safe.from_file file in
    let pk = element_of "group_public_key" (hexf j "group_public_key") in
    let msg = str (mem "message" j) in
    let sg = hexf j "signature" in
    let ours = F.verify ~group_public_key:pk ~msg sg in
    Printf.printf "  their signature, our verifier:            %s\n"
      (if ours then "ACCEPT" else "REJECT");
    let reference_ok =
      match R.reference with
      | None -> true
      | Some (name, verify) ->
          let ok = verify ~group_public_key:(El.serialize pk) ~msg sg in
          Printf.printf "  their signature, %-25s%s\n" (name ^ ":")
            (if ok then "ACCEPT" else "REJECT");
          ok
    in
    if not (ours && reference_ok) then exit 1

  (* their key material -> our signing *)
  let sign_with_theirs file threshold =
    let j = Yojson.Safe.from_file file in
    let pk = element_of "group_public_key" (hexf j "group_public_key") in
    let msg = str (mem "message" j) in
    let shares =
      match mem "shares" j with
      | `List l ->
          List.map
            (fun s ->
              ( scalar_of "identifier" (hexf s "identifier"),
                scalar_of "signing_share" (hexf s "signing_share"),
                element_of "verifying_share" (hexf s "verifying_share") ))
            l
      | _ -> die "shares is not a list"
    in
    (* Their verifying shares must match what we derive from their signing shares: if
     that fails, the two implementations disagree about scalar encoding and nothing
     below would mean anything. *)
    List.iter
      (fun (id, share, vs) ->
        if not (El.equal (El.scalar_mul_base share) vs) then
          die
            "verifying share for identifier %s does not match its signing share"
            (Ohex.encode (Sc.serialize id)))
      shares;
    let signers = List.filteri (fun i _ -> i < threshold) shares in
    let rand = Mpc.Rand.v Mirage_crypto_rng.generate in
    let commits =
      List.map
        (fun (id, share, vs) ->
          match F.commit rand ~secret:share with
          | Ok (nonces, c) -> (id, share, vs, nonces, c)
          | Error _ -> die "randomness source failed")
        signers
    in
    let cl =
      match
        E.commitment_list (List.map (fun (id, _, _, _, c) -> (id, c)) commits)
      with
      | Ok cl -> cl
      | Error _ -> die "could not build the commitment list"
    in
    let sig_shares =
      List.map
        (fun (id, share, _, nonces, _) ->
          match
            F.sign ~id ~share ~group_public_key:pk ~nonces ~msg
              ~commitment_list:cl
          with
          | Ok z -> z
          | Error _ -> die "signing failed")
        commits
    in
    let bf = F.binding_factors ~group_public_key:pk ~commitment_list:cl ~msg in
    let gc = F.group_commitment ~commitment_list:cl ~binding_factors:bf in
    let sg = F.aggregate ~group_commitment:gc sig_shares in
    if not (F.verify ~group_public_key:pk ~msg sg) then
      die "we produced a signature our own verifier rejects";
    (* Emitted for their verifier to judge. *)
    Printf.printf "%s\n%s\n%s\n"
      (Ohex.encode (El.serialize pk))
      msg (Ohex.encode sg)

  (* their DKG round 1 -> our proof-of-knowledge verifier

   RFC 9591 specifies the DKG only in an appendix, publishes no test vectors for it,
   and does not fix the proof-of-knowledge challenge hash. So this is the one part of
   the protocol where agreeing with the specification is not enough to agree with
   anyone else, and the only way to know we match is to check against an implementation
   that made the same choice. If the two challenge constructions differ by a byte,
   every verification here fails. *)
  let verify_their_dkg file =
    let j = Yojson.Safe.from_file file in
    let entries = match j with `List l -> l | _ -> die "expected a list" in
    let ok = ref true in
    List.iter
      (fun e ->
        let id = scalar_of "identifier" (hexf e "identifier") in
        let commitment =
          match mem "commitment" e with
          | `List cs ->
              Array.of_list
                (List.map
                   (fun c -> element_of "commitment" (Ohex.decode (str c)))
                   cs)
          | _ -> die "commitment is not a list"
        in
        (* The proof is a Schnorr signature: SerializeElement(R) || SerializeScalar(z).
           Both widths are ciphersuite-dependent -- 32 + 32 on Ed25519, 33 + 32 on
           secp256k1, whose points are compressed SEC1 -- so take them from the suite. *)
        let pok = hexf e "pok" in
        let want = Suite.ne + Suite.ns in
        if String.length pok <> want then
          die "proof of knowledge is %d bytes, expected %d" (String.length pok)
            want;
        let pok_r = element_of "pok_r" (String.sub pok 0 Suite.ne) in
        let pok_mu = scalar_of "pok_mu" (String.sub pok Suite.ne Suite.ns) in
        let phi0 = commitment.(0) in
        (* The challenge, recomputed by us, from our own hdkg. *)
        let c =
          Suite.hdkg
            (String.concat ""
               [ Sc.serialize id; El.serialize phi0; El.serialize pok_r ])
        in
        (* R == mu*G - c*phi0 *)
        let good =
          El.equal pok_r
            (El.sub (El.scalar_mul_base pok_mu) (El.scalar_mul c phi0))
        in
        if not good then ok := false;
        (* Identifiers are small, and the two ciphersuites serialise them with
           opposite endianness, so trim the zero bytes from both ends rather than
           assuming which end carries the value. *)
        let label =
          let h = Ohex.encode (Sc.serialize id) in
          let n = String.length h in
          let rec lo i =
            if i + 2 <= n && String.sub h i 2 = "00" then lo (i + 2) else i
          in
          let rec hi j =
            if j - 2 >= 0 && String.sub h (j - 2) 2 = "00" then hi (j - 2)
            else j
          in
          let i = lo 0 and j = hi n in
          if i < j then String.sub h i (j - i) else "00"
        in
        Printf.printf "  participant %s proof of knowledge: %s\n" label
          (if good then "ACCEPT" else "REJECT"))
      entries;
    if not !ok then exit 1
end

(* A first-class module needs a named signature. *)
module type CHECKS = sig
  val verify_theirs : string -> unit
  val sign_with_theirs : string -> int -> unit
  val verify_their_dkg : string -> unit
end

module Ed =
  Make
    (Mpc_ed25519.Suite)
    (struct
      let reference =
        Some
          ( "stock RFC 8032 verifier",
            fun ~group_public_key ~msg sg ->
              match Mirage_crypto_ec.Ed25519.pub_of_octets group_public_key with
              | Ok key -> Mirage_crypto_ec.Ed25519.verify ~key sg ~msg
              | Error _ -> false )
    end)

module Sk =
  Make
    (Mpc_secp256k1.Suite)
    (struct
      let reference = None
    end)

let () =
  Mirage_crypto_rng_unix.use_default ();
  let run (module M : CHECKS) = function
    | [ "verify-theirs"; file ] -> M.verify_theirs file
    | [ "sign-with-theirs"; file; t ] ->
        M.sign_with_theirs file (int_of_string t)
    | [ "verify-their-dkg"; file ] -> M.verify_their_dkg file
    | _ ->
        prerr_endline
          "usage: interop SUITE verify-theirs FILE | SUITE sign-with-theirs \
           FILE T | SUITE verify-their-dkg FILE     (SUITE = ed25519 | \
           secp256k1)";
        exit 2
  in
  match Array.to_list Sys.argv with
  | _ :: "ed25519" :: rest -> run (module Ed : CHECKS) rest
  | _ :: "secp256k1" :: rest -> run (module Sk : CHECKS) rest
  | _ :: rest -> run (module Ed : CHECKS) rest
  | [] -> exit 2
