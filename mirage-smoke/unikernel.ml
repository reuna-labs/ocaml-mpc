(* A Solo5 smoke test for ocaml-mpc.

   Two things are being proved, and only two. First, that the protocol core, the
   Ed25519 ciphersuite and the Lwt transport link and run in a unikernel -- no Unix,
   no missing symbol, no C stub that only exists on a hosted platform. Second, that
   the arithmetic gives the same answers there as it does on the host: the RFC 9591
   known-answer vector is checked in-kernel, so a cross-compilation that silently
   changed a result would fail here rather than in production.

   There is no network. Peers talk over an in-memory channel, because the transport is
   already covered by the socket tests on the host and adding a device stack here would
   only broaden what can go wrong without broadening what is proved. *)

module Suite = Mpc_ed25519.Suite
module Suite_k1 = Mpc_secp256k1.Suite
module Sc = Suite.Scalar
module El = Suite.Element
module Sess = Mpc.Session
module F = Mpc_frost.Core.Make (Suite)
module D = Mpc_frost.Dealer.Make (Suite)
module K = Mpc_frost.Keygen.Make (Suite)
module Sg = Mpc_frost.Sign.Make (Suite)

let of_hex h =
  String.init
    (String.length h / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

let peer n = Result.get_ok (Sess.peer n)
let id n = Result.get_ok (Sc.of_int n)
let rand () = Mpc.Rand.v Mirage_crypto_rng.generate

let fixed_rand values =
  let remaining = ref values in
  Mpc.Rand.v (fun n ->
      match !remaining with
      | v :: tl when String.length v = n ->
          remaining := tl;
          v
      | _ -> failwith "fixed_rand: unexpected request")

(* RFC 9591 Appendix E.1, FROST(Ed25519, SHA-512). Kept inline rather than read from a
   file: a unikernel has no filesystem, and the point is to check the arithmetic, not
   the storage stack. *)
let vector_group_secret =
  of_hex "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304"

let vector_coefficient =
  of_hex "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204"

let vector_group_public =
  of_hex "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"

let vector_message = of_hex "74657374"

let vector_randomness =
  List.map of_hex
    [
      "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec";
      "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501";
      "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f";
      "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775";
    ]

let vector_signature =
  of_hex
    "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"

let check name cond = if cond then Ok () else Error name

let known_answer () =
  let secret = Result.get_ok (Sc.deserialize vector_group_secret) in
  let a1 = Result.get_ok (Sc.deserialize vector_coefficient) in
  let packages, pkp =
    Result.get_ok
      (D.of_coefficients ~coefficients:[| secret; a1 |]
         ~ids:[ id 1; id 2; id 3 ])
  in
  let ( let& ) r f = match r with Error _ as e -> e | Ok () -> f () in
  let& () =
    check "group public key"
      (String.equal (El.serialize pkp.D.pk) vector_group_public)
  in
  (* The vector signs with participants 1 and 3. *)
  let signers = List.filteri (fun i _ -> i <> 1) packages in
  let r = fixed_rand vector_randomness in
  let commits =
    List.map
      (fun (kp : D.key_package) ->
        let nonces, c = Result.get_ok (F.commit r ~secret:kp.D.share) in
        (kp, nonces, c))
      signers
  in
  let cl =
    Result.get_ok
      (F.E.commitment_list (List.map (fun (kp, _, c) -> (kp.D.id, c)) commits))
  in
  let shares =
    List.map
      (fun ((kp : D.key_package), nonces, _) ->
        Result.get_ok
          (F.sign ~id:kp.D.id ~share:kp.D.share ~group_public_key:pkp.D.pk
             ~nonces ~msg:vector_message ~commitment_list:cl))
      commits
  in
  let bf =
    F.binding_factors ~group_public_key:pkp.D.pk ~commitment_list:cl
      ~msg:vector_message
  in
  let gc = F.group_commitment ~commitment_list:cl ~binding_factors:bf in
  let sg = F.aggregate ~group_commitment:gc shares in
  let& () =
    check "signature matches the vector" (String.equal sg vector_signature)
  in
  let& () =
    check "our own verifier accepts it"
      (F.verify ~group_public_key:pkp.D.pk ~msg:vector_message sg)
  in
  check "RFC 8032 verifier accepts it"
    (match Mirage_crypto_ec.Ed25519.pub_of_octets (El.serialize pkp.D.pk) with
    | Ok k -> Mirage_crypto_ec.Ed25519.verify ~key:k sg ~msg:vector_message
    | Error _ -> false)

(* An in-memory network: enough to drive both state machines to completion without a
   device stack. Delivery is immediate and in order, which is all this needs to be. *)
let drive (type t out)
    (module M : Mpc.Session.MACHINE with type t = t and type out = out)
    (nodes : (Sess.peer * t) list) : (Sess.peer * out) list =
  let states = Hashtbl.create 8 in
  List.iter (fun (p, m) -> Hashtbl.replace states p m) nodes;
  let peers = List.map fst nodes in
  let outputs = ref [] in
  let queue = Queue.create () in
  let record src (m, evs) =
    Hashtbl.replace states src m;
    List.iter
      (fun ev ->
        match ev with
        | Mpc.Session.Output o -> outputs := (src, o) :: !outputs
        | Mpc.Session.Aborted _ -> ()
        | Mpc.Session.Send { to_; msg; _ } ->
            let dsts =
              match to_ with
              | `Peer p -> [ p ]
              | `All -> List.filter (fun q -> q <> src) peers
            in
            List.iter (fun d -> Queue.add (d, msg) queue) dsts)
      evs
  in
  List.iter
    (fun p ->
      match M.step (Hashtbl.find states p) Mpc.Session.Start with
      | Ok r -> record p r
      | Error _ -> ())
    peers;
  let steps = ref 0 in
  while (not (Queue.is_empty queue)) && !steps < 10_000 do
    incr steps;
    let dst, msg = Queue.pop queue in
    match M.step (Hashtbl.find states dst) (Mpc.Session.Recv msg) with
    | Ok r -> record dst r
    | Error _ -> ()
  done;
  List.rev !outputs

let dkg_then_sign () =
  let n = 3 and threshold = 2 in
  let all = List.init n (fun i -> peer (i + 1)) in
  let id_of_peer p = Some (id (Sess.peer_to_int p)) in
  let session =
    Sess.derive_session_id ~domain:"smoke-dkg" ~group_public_key:""
      ~participants:all ~context:"2-of-3" ~nonce:(String.make 32 '\001')
  in
  let nodes =
    List.map
      (fun p ->
        ( p,
          Result.get_ok
            (K.create (rand ())
               {
                 K.self = p;
                 peers = all;
                 session;
                 threshold;
                 identifier = id (Sess.peer_to_int p);
                 id_of_peer;
               }) ))
      all
  in
  let outs = drive (module K) nodes in
  let ( let& ) r f = match r with Error _ as e -> e | Ok () -> f () in
  let& () = check "every party produced a key" (List.length outs = n) in
  let pk = (snd (List.hd outs)).K.group_public_key in
  let& () =
    check "parties agree on the group key"
      (List.for_all (fun (_, o) -> El.equal o.K.group_public_key pk) outs)
  in
  let signers = List.filteri (fun i _ -> i < threshold) outs |> List.map fst in
  let coordinator = List.hd signers in
  let msg = "a unikernel signed this" in
  let sign_session =
    Sess.derive_session_id ~domain:"smoke-sign"
      ~group_public_key:(El.serialize pk) ~participants:signers ~context:msg
      ~nonce:(String.make 32 '\002')
  in
  let snodes =
    List.filter_map
      (fun (p, (o : K.out)) ->
        if not (List.mem p signers) then None
        else
          Some
            ( p,
              Result.get_ok
                (Sg.create (rand ())
                   {
                     Sg.self = p;
                     coordinator;
                     signers;
                     session = sign_session;
                     identifier = o.K.identifier;
                     signing_share = Some o.K.signing_share;
                     group_public_key = pk;
                     verification_shares = o.K.verification_shares;
                     id_of_peer;
                     msg;
                   }) ))
      outs
  in
  let sigs = drive (module Sg) snodes in
  let& () = check "a signature was produced" (sigs <> []) in
  let sg = snd (List.hd sigs) in
  check "RFC 8032 verifier accepts the DKG-derived signature"
    (match Mirage_crypto_ec.Ed25519.pub_of_octets (El.serialize pk) with
    | Ok k -> Mirage_crypto_ec.Ed25519.verify ~key:k sg ~msg
    | Error _ -> false)

(* Exercise the transport's framing as well. It is not used to talk to anything here --
   there is no network -- but referencing it forces mpc-lwt to be linked, which is what
   turns "mpc-lwt was installed for this target" into "mpc-lwt cross-compiles and
   runs". *)
let framing_roundtrip () =
  let payloads = [ ""; "x"; String.make 1000 'y'; String.init 256 Char.chr ] in
  let dec = Mpc_lwt.Framing.create () in
  List.iter
    (fun p -> Mpc_lwt.Framing.feed dec (Mpc_lwt.Framing.encode_string p))
    payloads;
  let rec drain acc =
    match Mpc_lwt.Framing.next dec with
    | `Message m -> drain (Cstruct.to_string m :: acc)
    | `Need_more -> Ok (List.rev acc)
    | `Error e -> Error e
  in
  match drain [] with
  | Error e -> Error e
  | Ok got ->
      if got = payloads then
        if Mpc_lwt.Framing.pending dec = 0 then Ok ()
        else Error "bytes left buffered after draining every frame"
      else Error "framed payloads did not round trip"

(* A second ciphersuite, exercised enough to prove it cross-compiles and computes the
   same answers here as on the host. The full RFC 9591 secp256k1 vector lives in the
   host test suite; what is checked in-kernel is that the C the suite depends on --
   fiat-crypto scalar arithmetic and the ECCKiila ladder -- links and runs under Solo5. *)
let secp256k1_sanity () =
  let module S = Suite_k1 in
  let ( let& ) r f = match r with Error _ as e -> e | Ok () -> f () in
  let two = Result.get_ok (S.Scalar.of_int 2) in
  let three = Result.get_ok (S.Scalar.of_int 3) in
  let& () =
    check "2 + 1 = 3" (S.Scalar.equal (S.Scalar.add two S.Scalar.one) three)
  in
  let& () =
    check "inversion"
      (match S.Scalar.invert three with
      | Ok i -> S.Scalar.equal (S.Scalar.mul three i) S.Scalar.one
      | Error _ -> false)
  in
  let g = S.Element.generator in
  let& () =
    check "2G = G + G" (S.Element.equal (S.Element.scalar_mul two g) (S.Element.add g g))
  in
  let& () =
    check "compressed points are 33 bytes" (String.length (S.Element.serialize g) = 33)
  in
  (* hash_to_field, the piece this suite needs and Ed25519 does not. *)
  check "hash_to_field is deterministic and non-zero"
    (let a = S.h1 "abc" and b = S.h1 "abc" and c = S.h1 "abd" in
     S.Scalar.equal a b
     && (not (S.Scalar.equal a c))
     && not (S.Scalar.is_zero a))

module Main = struct
  (* The randomness source is initialised by the caller, not here. Mirage's generated
     main.ml calls Mirage_crypto_rng_mirage.initialize before invoking [start], and
     that function refuses to run twice -- initialising again here booted the unikernel
     and then killed it with "entropy collection already running". On the host,
     test/smoke/run_smoke.ml does the equivalent. *)
  let start () =
    Printf.printf
      "== ocaml-mpc smoke test (OCaml -> MirageOS -> Solo5): FROST ==\n";
    let report name = function
      | Ok () ->
          Printf.printf "  [PASS] %s\n" name;
          true
      | Error what ->
          Printf.printf "  [FAIL] %s: %s\n" name what;
          false
    in
    let a = report "RFC 9591 known-answer vector (Ed25519)" (known_answer ()) in
    let k = report "secp256k1 arithmetic" (secp256k1_sanity ()) in
    let f = report "transport framing round trip" (framing_roundtrip ()) in
    let b =
      report "distributed key generation, then threshold signing" (dkg_then_sign ())
    in
    if a && k && f && b then begin
      Printf.printf "  all checks passed\n%!";
      Lwt.return_unit
    end
    else begin
      Printf.printf "  FAILED\n%!";
      exit 1
    end
end
