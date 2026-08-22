(** The signing state machine, driven through the deterministic simulator.

    The tests that carry the security argument here are
    {!t_nonce_reuse_rejected} -- which replays a round-2 message into a
    {e retained copy} of the pre-step state, the case purity alone does not
    cover -- and {!t_crash_wipes}, which asserts erasure rather than assuming
    it. *)

open Testutil.Ed25519
module D = Mpc_frost.Dealer.Make (Mpc_ed25519.Suite)
module Sg = Mpc_frost.Sign.Make (Mpc_ed25519.Suite)
module Sess = Mpc.Session
module Net = Mpc_sim.Net.Make (Sg)

let peer n = Result.get_ok (Sess.peer n)

let setup ~seed ~threshold ~n =
  let r = rand_of_seed seed in
  let secret = Result.get_ok (Sc.random r) in
  let packages, pkp =
    Result.get_ok (D.generate r ~secret ~threshold ~ids:(ids n))
  in
  (packages, pkp)

(* Build one signing session per chosen signer, with signer 1 also acting as
   coordinator -- the RFC's model, and the one that exercises the local-delivery path
   where the coordinator must apply its own broadcast. *)
let sessions ~seed ~packages ~pkp ~signer_ixs ~msg =
  let signers = List.map (fun i -> peer (i + 1)) signer_ixs in
  let coordinator = List.hd signers in
  let session =
    Sess.derive_session_id ~domain:"frost-sign"
      ~group_public_key:(El.serialize pkp.D.pk) ~participants:signers
      ~context:msg ~nonce:(String.make 32 '\007')
  in
  let id_of_peer p = Some (id (Sess.peer_to_int p)) in
  List.map
    (fun i ->
      let kp = List.nth packages i in
      let self = peer (i + 1) in
      let cfg =
        {
          Sg.self;
          coordinator;
          signers;
          session;
          identifier = kp.D.id;
          signing_share = Some kp.D.share;
          group_public_key = pkp.D.pk;
          verification_shares = pkp.D.verification_shares;
          id_of_peer;
          msg;
        }
      in
      ( self,
        Result.get_ok (Sg.create (rand_of_seed (seed ^ string_of_int i)) cfg) ))
    signer_ixs

let msg = "sans-IO threshold signing"

let run_ok ~seed ~schedule ~signer_ixs =
  let packages, pkp = setup ~seed:(seed ^ "-key") ~threshold:3 ~n:5 in
  let nodes = sessions ~seed ~packages ~pkp ~signer_ixs ~msg in
  let out = Net.run ~seed ~schedule (List.map (fun (p, m) -> (p, m)) nodes) in
  (out, pkp, nodes)

let check_signature pkp (out : Net.outcome) label =
  Alcotest.(check bool) (label ^ ": no aborts") true (out.Net.aborts = []);
  (* Every signer ends with the aggregate: the coordinator by construction, the rest
     because it broadcasts the result and each verifies it independently. *)
  Alcotest.(check int)
    (label ^ ": every signer obtained the signature")
    (List.length out.Net.final)
    (List.length out.Net.outputs);
  let _, sg = List.hd out.Net.outputs in
  List.iter
    (fun (_, s) ->
      Alcotest.(check string) (label ^ ": signers agree") (hex sg) (hex s))
    out.Net.outputs;
  let ed_pub =
    Result.get_ok
      (Mirage_crypto_ec.Ed25519.pub_of_octets (El.serialize pkp.D.pk))
  in
  Alcotest.(check bool)
    (label ^ ": RFC 8032 verifier accepts it")
    true
    (Mirage_crypto_ec.Ed25519.verify ~key:ed_pub sg ~msg)

let t_happy_path () =
  List.iter
    (fun (label, schedule) ->
      let out, pkp, _ =
        run_ok ~seed:("happy-" ^ label) ~schedule ~signer_ixs:[ 0; 1; 2 ]
      in
      check_signature pkp out label)
    [
      ("fifo", Mpc_sim.Net.Fifo);
      ("reversed", Mpc_sim.Net.Reversed);
      ("shuffled", Mpc_sim.Net.Shuffled { window = 8 });
    ]

let t_every_subset () =
  let packages, pkp = setup ~seed:"subsets-key" ~threshold:3 ~n:5 in
  let rec combos k xs =
    if k = 0 then [ [] ]
    else
      match xs with
      | [] -> []
      | x :: tl -> List.map (fun c -> x :: c) (combos (k - 1) tl) @ combos k tl
  in
  List.iteri
    (fun i signer_ixs ->
      let seed = Printf.sprintf "subset%d" i in
      let nodes = sessions ~seed ~packages ~pkp ~signer_ixs ~msg in
      let out =
        Net.run ~seed ~schedule:(Mpc_sim.Net.Shuffled { window = 6 }) nodes
      in
      check_signature pkp out (Printf.sprintf "subset %d" i))
    (combos 3 [ 0; 1; 2; 3; 4 ])

let t_reorder_and_duplicate () =
  (* Duplicates are legitimate retransmissions and must not change the outcome. *)
  let packages, pkp = setup ~seed:"dup-key" ~threshold:3 ~n:5 in
  for i = 0 to 19 do
    let seed = Printf.sprintf "dup%d" i in
    let nodes = sessions ~seed ~packages ~pkp ~signer_ixs:[ 0; 1; 2 ] ~msg in
    let faults =
      [
        Mpc_sim.Net.Duplicate { party = peer (1 + (i mod 3)); round = i mod 2 };
      ]
    in
    let out =
      Net.run ~seed
        ~schedule:(Mpc_sim.Net.Shuffled { window = 8 })
        ~faults nodes
    in
    check_signature pkp out seed
  done

let t_drop_aborts_or_stalls () =
  (* Losing a participant's round-0 commitment must never yield a wrong signature. The
     coordinator either aborts or simply never completes; both are safe, and which one
     happens is the driver's timeout policy, not the core's. *)
  let packages, pkp = setup ~seed:"drop-key" ~threshold:3 ~n:5 in
  let seed = "drop" in
  let nodes = sessions ~seed ~packages ~pkp ~signer_ixs:[ 0; 1; 2 ] ~msg in
  let faults = [ Mpc_sim.Net.Drop { party = peer 3; round = 0 } ] in
  let out = Net.run ~seed ~schedule:Mpc_sim.Net.Fifo ~faults nodes in
  Alcotest.(check int) "no signature produced" 0 (List.length out.Net.outputs);
  ignore pkp

let t_timeout_names_the_missing () =
  let packages, pkp = setup ~seed:"to-key" ~threshold:3 ~n:5 in
  let nodes = sessions ~seed:"to" ~packages ~pkp ~signer_ixs:[ 0; 1; 2 ] ~msg in
  let coord_peer, coord = List.hd nodes in
  (* Start the coordinator alone: nobody else has sent a commitment. *)
  let coord, _ = Result.get_ok (Sg.step coord Sess.Start) in
  let missing = Sg.expected_from coord in
  Alcotest.(check bool)
    "peers 2 and 3 are outstanding" true
    (List.length missing = 2 && not (List.mem coord_peer missing));
  let coord, evs = Result.get_ok (Sg.step coord (Sess.Timeout 0)) in
  (match evs with
  | [ Sess.Aborted a ] ->
      Alcotest.(check bool) "timeout code" true (a.Sess.code = `Timeout);
      Alcotest.(check int)
        "names both missing peers" 2
        (List.length a.Sess.culprits)
  | _ -> Alcotest.fail "expected a timeout abort");
  (* A stale timeout for a round already left behind is not an error. *)
  let coord2, evs2 = Result.get_ok (Sg.step coord (Sess.Timeout 99)) in
  Alcotest.(check int)
    "terminal session ignores further input" 0 (List.length evs2);
  Alcotest.(check bool)
    "still aborted" true
    (match Sg.status coord2 with `Aborted _ -> true | _ -> false)

let t_nonce_reuse_rejected () =
  (* The case immutability does not cover: retain the state from before round 2 and
     step it a second time. The nonce cell is shared with the newer state value, so the
     replay must find it burned. *)
  let packages, pkp = setup ~seed:"reuse-key" ~threshold:3 ~n:5 in
  let nodes =
    sessions ~seed:"reuse" ~packages ~pkp ~signer_ixs:[ 0; 1; 2 ] ~msg
  in
  let participant = List.nth nodes 1 |> snd in
  let coord = List.hd nodes |> snd in
  (* Drive far enough that the coordinator has emitted a signing package. *)
  let participant, p_evs = Result.get_ok (Sg.step participant Sess.Start) in
  let coord, _ = Result.get_ok (Sg.step coord Sess.Start) in
  let third, t_evs =
    Result.get_ok (Sg.step (List.nth nodes 2 |> snd) Sess.Start)
  in
  ignore third;
  let send_of = function
    | [ Sess.Send { msg; _ } ] -> msg
    | _ -> Alcotest.fail "expected a Send"
  in
  let coord, _ = Result.get_ok (Sg.step coord (Sess.Recv (send_of p_evs))) in
  let coord, evs = Result.get_ok (Sg.step coord (Sess.Recv (send_of t_evs))) in
  let package =
    List.find_map
      (function Sess.Send { msg; to_ = `All; _ } -> Some msg | _ -> None)
      evs
    |> Option.get
  in
  ignore coord;
  Alcotest.(check bool)
    "nonce is live before signing" false
    (Sg.nonce_burned participant);
  let signed, evs1 = Result.get_ok (Sg.step participant (Sess.Recv package)) in
  Alcotest.(check int) "a share was produced" 1 (List.length evs1);
  Alcotest.(check bool)
    "nonce burned after signing" true (Sg.nonce_burned signed);
  (* Replay into the RETAINED pre-step value, not the post-step one. *)
  let replayed, evs2 =
    Result.get_ok (Sg.step participant (Sess.Recv package))
  in
  match evs2 with
  | [ Sess.Aborted a ] ->
      Alcotest.(check bool)
        "replay is refused" true
        (a.Sess.code = `Nonce_already_used);
      Alcotest.(check bool)
        "and the session is terminal" true
        (match Sg.status replayed with `Aborted _ -> true | _ -> false)
  | _ ->
      Alcotest.fail
        "replaying a signing package must not produce a second share"

let t_wrong_session_ignored () =
  let packages, pkp = setup ~seed:"xs-key" ~threshold:3 ~n:5 in
  let a = sessions ~seed:"xsA" ~packages ~pkp ~signer_ixs:[ 0; 1; 2 ] ~msg in
  let b =
    sessions ~seed:"xsB" ~packages ~pkp ~signer_ixs:[ 0; 1; 2 ]
      ~msg:(msg ^ " other")
  in
  let _, from_a = Result.get_ok (Sg.step (List.nth a 1 |> snd) Sess.Start) in
  let stolen =
    match from_a with
    | [ Sess.Send { msg; _ } ] -> msg
    | _ -> Alcotest.fail "send"
  in
  let coord_b, _ = Result.get_ok (Sg.step (List.hd b |> snd) Sess.Start) in
  let coord_b, evs = Result.get_ok (Sg.step coord_b (Sess.Recv stolen)) in
  Alcotest.(check int)
    "a message from another session is dropped" 0 (List.length evs);
  Alcotest.(check bool)
    "and the session keeps running" true
    (Sg.status coord_b = `Running)

let t_crash_wipes () =
  let packages, pkp = setup ~seed:"crash-key" ~threshold:3 ~n:5 in
  let seed = "crash" in
  let nodes = sessions ~seed ~packages ~pkp ~signer_ixs:[ 0; 1; 2 ] ~msg in
  let victim = peer 3 in
  let faults = [ Mpc_sim.Net.Crash { party = victim; after_round = 0 } ] in
  let out = Net.run ~seed ~schedule:Mpc_sim.Net.Fifo ~faults nodes in
  (* The fault must actually fire, or everything below passes vacuously. *)
  Alcotest.(check bool)
    "the victim really crashed" true
    (List.mem victim out.Net.crashed);
  Alcotest.(check int)
    "no signature after a crash" 0
    (List.length out.Net.outputs);
  (* The crashed node published a commitment and then died, so its nonce -- the thing
     that must never survive to be reused -- is gone. *)
  let victim_state = List.assoc victim out.Net.final in
  Alcotest.(check bool)
    "the crashed node's nonce is burned" true
    (Sg.nonce_burned victim_state);
  (* The coordinator is left waiting on the victim. A driver's timeout turns that into
     an abort that names it: this is the "one node drops off mid-computation" case. *)
  let coord_peer = peer 1 in
  let coord = List.assoc coord_peer out.Net.final in
  Alcotest.(check bool)
    "coordinator is still waiting" true
    (Sg.status coord = `Running);
  Alcotest.(check bool)
    "and it is waiting on the victim" true
    (List.mem victim (Sg.expected_from coord));
  let coord, evs =
    Result.get_ok (Sg.step coord (Sess.Timeout (Sg.round coord)))
  in
  (match evs with
  | [ Sess.Aborted a ] ->
      Alcotest.(check bool) "timeout abort" true (a.Sess.code = `Timeout);
      Alcotest.(check bool)
        "names the crashed party" true
        (List.mem victim a.Sess.culprits)
  | _ -> Alcotest.fail "expected the coordinator to time out");
  (* Every terminated session leaves no live nonce. Asserted, not assumed. *)
  List.iter
    (fun (p, m) ->
      match Sg.status m with
      | `Running -> ()
      | `Done | `Aborted _ ->
          Alcotest.(check bool)
            (Printf.sprintf "peer %d left no live nonce" (Sess.peer_to_int p))
            true (Sg.nonce_burned m))
    ((coord_peer, coord) :: out.Net.final)

let t_cancel_burns () =
  let packages, pkp = setup ~seed:"cancel-key" ~threshold:3 ~n:5 in
  let nodes =
    sessions ~seed:"cancel" ~packages ~pkp ~signer_ixs:[ 0; 1; 2 ] ~msg
  in
  let m = List.nth nodes 1 |> snd in
  let m, _ = Result.get_ok (Sg.step m Sess.Start) in
  Alcotest.(check bool) "nonce live after commit" false (Sg.nonce_burned m);
  let m, evs = Result.get_ok (Sg.step m Sess.Cancel) in
  Alcotest.(check bool)
    "cancel aborts" true
    (match evs with
    | [ Sess.Aborted a ] -> a.Sess.code = `Cancelled
    | _ -> false);
  Alcotest.(check bool) "and burns the nonce" true (Sg.nonce_burned m)

let suites =
  [
    ( "sign-machine",
      [
        Alcotest.test_case "happy path under three schedules" `Quick
          t_happy_path;
        Alcotest.test_case "every 3-of-5 subset" `Quick t_every_subset;
        Alcotest.test_case "reordering and duplication" `Quick
          t_reorder_and_duplicate;
        Alcotest.test_case "dropped commitment" `Quick t_drop_aborts_or_stalls;
        Alcotest.test_case "timeout names the missing" `Quick
          t_timeout_names_the_missing;
        Alcotest.test_case "nonce reuse rejected" `Quick t_nonce_reuse_rejected;
        Alcotest.test_case "cross-session replay ignored" `Quick
          t_wrong_session_ignored;
        Alcotest.test_case "crash leaves no live nonce" `Quick t_crash_wipes;
        Alcotest.test_case "cancel burns the nonce" `Quick t_cancel_burns;
      ] );
  ]
