(** The two-round Pedersen DKG.

    The property that matters is that the group key is never assembled anywhere:
    each party ends with a share, and the key exists only as a public element.
    {!t_dkg_then_sign} closes the loop by signing with DKG-produced shares and
    having a stock RFC 8032 verifier accept the result. *)

open Testutil.Ed25519

let hex = Ohex.encode

module K = Mpc_frost.Keygen.Make (Mpc_ed25519.Suite)
module Sg = Mpc_frost.Sign.Make (Mpc_ed25519.Suite)
module Sh = Mpc.Shamir.Make (Mpc_ed25519.Suite)
module Sess = Mpc.Session
module Msg = Mpc_frost.Msg.Make (Mpc_ed25519.Suite)
module Net = Mpc_sim.Net.Make (K)
module SignNet = Mpc_sim.Net.Make (Sg)

let peer n = Result.get_ok (Sess.peer n)
let id_of_peer p = Some (id (Sess.peer_to_int p))

let dkg_nodes ~seed ~n ~threshold =
  let peers = List.init n (fun i -> peer (i + 1)) in
  let session =
    Sess.derive_session_id ~domain:"frost-dkg" ~group_public_key:""
      ~participants:peers ~context:(string_of_int threshold)
      ~nonce:(String.make 32 '\003')
  in
  List.map
    (fun p ->
      let cfg =
        {
          K.self = p;
          peers;
          session;
          threshold;
          identifier = id (Sess.peer_to_int p);
          id_of_peer;
        }
      in
      ( p,
        Result.get_ok
          (K.create
             (rand_of_seed (seed ^ "-" ^ string_of_int (Sess.peer_to_int p)))
             cfg) ))
    peers

let run_dkg ~seed ?(schedule = Mpc_sim.Net.Fifo) ?(faults = []) ~n ~threshold ()
    =
  Net.run ~seed ~schedule ~faults (dkg_nodes ~seed ~n ~threshold)

let t_dkg_agrees () =
  List.iter
    (fun (label, schedule) ->
      let out = run_dkg ~seed:("dkg-" ^ label) ~schedule ~n:5 ~threshold:3 () in
      Alcotest.(check bool) (label ^ ": no aborts") true (out.Net.aborts = []);
      Alcotest.(check int)
        (label ^ ": every party produced a key")
        5
        (List.length out.Net.outputs);
      let keys =
        List.map (fun (_, o) -> o.K.group_public_key) out.Net.outputs
      in
      let first = List.hd keys in
      List.iter
        (fun k -> Alcotest.check el (label ^ ": same group key") first k)
        keys;
      (* Each party's verification share must be consistent with its signing share, and
         with what the others can derive from the public commitments alone. *)
      List.iter
        (fun (_, o) ->
          Alcotest.check el
            (label ^ ": verification share")
            (El.scalar_mul_base o.K.signing_share)
            o.K.verification_share;
          let from_commitment =
            List.assoc_opt o.K.identifier o.K.verification_shares |> Option.get
          in
          Alcotest.check el
            (label ^ ": derivable from public commitments")
            o.K.verification_share from_commitment)
        out.Net.outputs)
    [
      ("fifo", Mpc_sim.Net.Fifo);
      ("reversed", Mpc_sim.Net.Reversed);
      ("shuffled", Mpc_sim.Net.Shuffled { window = 10 });
    ]

let t_dkg_shares_interpolate () =
  (* Any t of the shares reconstruct a secret whose public image is the group key --
     which is exactly what a threshold scheme must guarantee, and which no party ever
     computes during the protocol. *)
  let out = run_dkg ~seed:"interp" ~n:5 ~threshold:3 () in
  let outs = List.map snd out.Net.outputs in
  let rec combos k xs =
    if k = 0 then [ [] ]
    else
      match xs with
      | [] -> []
      | x :: tl -> List.map (fun c -> x :: c) (combos (k - 1) tl) @ combos k tl
  in
  let pk = (List.hd outs).K.group_public_key in
  List.iter
    (fun sub ->
      let shares =
        List.map
          (fun o -> { Sh.id = o.K.identifier; value = o.K.signing_share })
          sub
      in
      let secret = Result.get_ok (Sh.interpolate_secret shares) in
      Alcotest.check el "interpolated secret matches the group key" pk
        (El.scalar_mul_base secret))
    (combos 3 outs)

let t_dkg_then_sign () =
  let out = run_dkg ~seed:"dkg-sign" ~n:5 ~threshold:3 () in
  let outs = List.map (fun (p, o) -> (p, o)) out.Net.outputs in
  let signers = List.filteri (fun i _ -> i < 3) outs |> List.map fst in
  let coordinator = List.hd signers in
  let msg = "signed with keys that were never assembled" in
  let pk = (snd (List.hd outs)).K.group_public_key in
  let session =
    Sess.derive_session_id ~domain:"frost-sign"
      ~group_public_key:(El.serialize pk) ~participants:signers ~context:msg
      ~nonce:(String.make 32 '\011')
  in
  let nodes =
    List.filter_map
      (fun (p, o) ->
        if not (List.mem p signers) then None
        else
          let cfg =
            {
              Sg.self = p;
              coordinator;
              signers;
              session;
              identifier = o.K.identifier;
              signing_share = Some o.K.signing_share;
              group_public_key = o.K.group_public_key;
              verification_shares = o.K.verification_shares;
              id_of_peer;
              msg;
            }
          in
          Some
            ( p,
              Result.get_ok
                (Sg.create
                   (rand_of_seed ("s" ^ string_of_int (Sess.peer_to_int p)))
                   cfg) ))
      outs
  in
  let res =
    SignNet.run ~seed:"dkgsign"
      ~schedule:(Mpc_sim.Net.Shuffled { window = 8 })
      nodes
  in
  Alcotest.(check bool) "no aborts" true (res.SignNet.aborts = []);
  Alcotest.(check int)
    "every signer obtained the signature" 3
    (List.length res.SignNet.outputs);
  let _, sg = List.hd res.SignNet.outputs in
  List.iter
    (fun (_, s) -> Alcotest.(check string) "signers agree" (hex sg) (hex s))
    res.SignNet.outputs;
  let ed_pub =
    Result.get_ok (Mirage_crypto_ec.Ed25519.pub_of_octets (El.serialize pk))
  in
  Alcotest.(check bool)
    "stock RFC 8032 verifier accepts it" true
    (Mirage_crypto_ec.Ed25519.verify ~key:ed_pub sg ~msg)

let t_dkg_is_atomic () =
  (* A crash mid-DKG must leave nobody with a key and nobody holding a partial sum.
     A partial sum is a linear function of other parties' secrets and combines across
     aborted runs, so "some parties finished" would be a real leak, not an
     inconvenience. *)
  let victim = peer 2 in
  let out =
    run_dkg ~seed:"atomic"
      ~faults:[ Mpc_sim.Net.Crash { party = victim; after_round = 0 } ]
      ~n:4 ~threshold:3 ()
  in
  Alcotest.(check bool) "the crash fired" true (List.mem victim out.Net.crashed);
  Alcotest.(check int) "nobody produced a key" 0 (List.length out.Net.outputs);
  (* Drive every survivor to its timeout and check it kept nothing. *)
  List.iter
    (fun (p, m) ->
      let m =
        match K.status m with
        | `Running -> fst (Result.get_ok (K.step m (Sess.Timeout (K.round m))))
        | _ -> m
      in
      Alcotest.(check bool)
        (Printf.sprintf "peer %d retained no polynomial" (Sess.peer_to_int p))
        true (K.secrets_cleared m))
    out.Net.final

let t_bad_share_is_attributed () =
  (* Hand one party a share that does not match the sender's commitment. It must abort
     naming the sender, not fail anonymously. *)
  let nodes = dkg_nodes ~seed:"badshare" ~n:3 ~threshold:2 in
  let started =
    List.map (fun (p, m) -> (p, Result.get_ok (K.step m Sess.Start))) nodes
  in
  let bcast p =
    List.find_map
      (function Sess.Send { to_ = `All; msg; _ } -> Some msg | _ -> None)
      (snd (List.assoc p started))
    |> Option.get
  in
  let target = peer 1 and src = peer 2 in
  let session = (bcast src).Msg.session in
  (* Drive the target through round 1 so that it is expecting shares. *)
  let m = fst (List.assoc target started) in
  let m, _ = Result.get_ok (K.step m (Sess.Recv (bcast src))) in
  let m, _ = Result.get_ok (K.step m (Sess.Recv (bcast (peer 3)))) in
  Alcotest.(check int) "target has entered round 2" 1 (K.round m);
  let bad =
    Msg.make ~session ~round:1 ~src ~dst:target
      (Msg.Dkg_share { value = Sc.one })
  in
  let m, evs = Result.get_ok (K.step m (Sess.Recv bad)) in
  (match evs with
  | [ Sess.Aborted a ] ->
      Alcotest.(check bool) "bad share detected" true (a.Sess.code = `Bad_share);
      Alcotest.(check bool)
        "and attributed to the sender" true
        (a.Sess.culprits = [ src ])
  | _ -> Alcotest.fail "a share that does not match its commitment must abort");
  Alcotest.(check bool) "and nothing was retained" true (K.secrets_cleared m)

let t_equivocation_detected () =
  let nodes = dkg_nodes ~seed:"equiv" ~n:3 ~threshold:2 in
  let started =
    List.map (fun (p, m) -> (p, Result.get_ok (K.step m Sess.Start))) nodes
  in
  let bcast p =
    List.find_map
      (function Sess.Send { to_ = `All; msg; _ } -> Some msg | _ -> None)
      (snd (List.assoc p started))
    |> Option.get
  in
  let target = peer 1 in
  let m = fst (List.assoc target started) in
  let m, _ = Result.get_ok (K.step m (Sess.Recv (bcast (peer 2)))) in
  (* A byte-identical resend is a legitimate retransmission and must be ignored. *)
  let m, evs = Result.get_ok (K.step m (Sess.Recv (bcast (peer 2)))) in
  Alcotest.(check int) "duplicate ignored" 0 (List.length evs);
  Alcotest.(check bool) "session still running" true (K.status m = `Running);
  (* A different commitment from the same peer for the same round is equivocation: two
     commitments mean two different keys, so the protocol cannot continue. *)
  let forged = { (bcast (peer 3)) with Msg.src = peer 2 } in
  let m, evs = Result.get_ok (K.step m (Sess.Recv forged)) in
  (match evs with
  | [ Sess.Aborted a ] ->
      Alcotest.(check bool)
        "equivocation detected" true
        (a.Sess.code = `Equivocation);
      Alcotest.(check bool) "attributed" true (a.Sess.culprits = [ peer 2 ])
  | _ -> Alcotest.fail "two different round-1 commitments must abort");
  Alcotest.(check bool) "nothing retained" true (K.secrets_cleared m)

let suites =
  [
    ( "dkg",
      [
        Alcotest.test_case "parties agree on the group key" `Quick t_dkg_agrees;
        Alcotest.test_case "shares interpolate to the key" `Quick
          t_dkg_shares_interpolate;
        Alcotest.test_case "DKG then sign, verified by RFC 8032" `Quick
          t_dkg_then_sign;
        Alcotest.test_case "abort is atomic" `Quick t_dkg_is_atomic;
        Alcotest.test_case "bad share is attributed" `Quick
          t_bad_share_is_attributed;
        Alcotest.test_case "equivocation detected" `Quick
          t_equivocation_detected;
      ] );
  ]
