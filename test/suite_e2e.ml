(** End-to-end for any ciphersuite: distributed key generation, then threshold
    signing, judged by an independent verifier.

    This is the check that says a new ciphersuite actually works, as opposed to
    merely satisfying the module type. It exercises the whole stack — VSS, the
    proof of knowledge, both state machines, the wire codec, aggregation — over
    whatever curve it is instantiated at. *)

module Make
    (C : Mpc.Group.CIPHERSUITE)
    (V : sig
      val name : string

      val verify_with_reference :
        group_public_key:string -> msg:string -> string -> bool
    end) =
struct
  include Testutil.Make (C)
  module K = Mpc_frost.Keygen.Make (C)
  module Sg = Mpc_frost.Sign.Make (C)
  module Sh = Mpc.Shamir.Make (C)
  module Sess = Mpc.Session
  module KNet = Mpc_sim.Net.Make (K)
  module SNet = Mpc_sim.Net.Make (Sg)

  let peer n = Result.get_ok (Sess.peer n)
  let id_of_peer p = Some (id (Sess.peer_to_int p))

  let run_dkg ~seed ~n ~threshold ~schedule =
    let peers = List.init n (fun i -> peer (i + 1)) in
    let session =
      Sess.derive_session_id ~domain:"e2e-dkg" ~group_public_key:""
        ~participants:peers ~context:(string_of_int threshold)
        ~nonce:(String.make 32 '\013')
    in
    let nodes =
      List.map
        (fun p ->
          ( p,
            Result.get_ok
              (K.create
                 (rand_of_seed (seed ^ string_of_int (Sess.peer_to_int p)))
                 {
                   K.self = p;
                   peers;
                   session;
                   threshold;
                   identifier = id (Sess.peer_to_int p);
                   id_of_peer;
                 }) ))
        peers
    in
    KNet.run ~seed ~schedule nodes

  let t_dkg_then_sign () =
    List.iter
      (fun (label, schedule) ->
        let n = 5 and threshold = 3 in
        let seed = V.name ^ "-" ^ label in
        let out = run_dkg ~seed ~n ~threshold ~schedule in
        Alcotest.(check bool) (label ^ ": no aborts") true (out.KNet.aborts = []);
        Alcotest.(check int)
          (label ^ ": every party has a key")
          n
          (List.length out.KNet.outputs);
        let pk = (snd (List.hd out.KNet.outputs)).K.group_public_key in
        List.iter
          (fun (_, (o : K.out)) ->
            Alcotest.check el
              (label ^ ": same group key")
              pk o.K.group_public_key;
            Alcotest.check el
              (label ^ ": verification share")
              (El.scalar_mul_base o.K.signing_share)
              o.K.verification_share)
          out.KNet.outputs;
        (* Any threshold-sized subset of the shares reconstructs a secret whose public
           image is the group key -- a value no party ever computes. *)
        let outs = List.map snd out.KNet.outputs in
        let subset = List.filteri (fun i _ -> i < threshold) outs in
        let shares =
          List.map
            (fun o -> { Sh.id = o.K.identifier; value = o.K.signing_share })
            subset
        in
        Alcotest.check el
          (label ^ ": shares interpolate to the key")
          pk
          (El.scalar_mul_base (Result.get_ok (Sh.interpolate_secret shares)));
        (* Now sign with a threshold subset. *)
        let signers =
          List.filteri (fun i _ -> i < threshold) out.KNet.outputs
        in
        let signer_peers = List.map fst signers in
        let coordinator = List.hd signer_peers in
        let msg = "end to end over " ^ V.name in
        let sign_session =
          Sess.derive_session_id ~domain:"e2e-sign"
            ~group_public_key:(El.serialize pk) ~participants:signer_peers
            ~context:msg ~nonce:(String.make 32 '\014')
        in
        let nodes =
          List.map
            (fun (p, (o : K.out)) ->
              ( p,
                Result.get_ok
                  (Sg.create
                     (rand_of_seed
                        (seed ^ "s" ^ string_of_int (Sess.peer_to_int p)))
                     {
                       Sg.self = p;
                       coordinator;
                       signers = signer_peers;
                       session = sign_session;
                       identifier = o.K.identifier;
                       signing_share = Some o.K.signing_share;
                       group_public_key = pk;
                       verification_shares = o.K.verification_shares;
                       id_of_peer;
                       msg;
                     }) ))
            signers
        in
        let res = SNet.run ~seed ~schedule nodes in
        Alcotest.(check bool)
          (label ^ ": signing had no aborts")
          true (res.SNet.aborts = []);
        Alcotest.(check int)
          (label ^ ": every signer has the signature")
          threshold
          (List.length res.SNet.outputs);
        let sg = snd (List.hd res.SNet.outputs) in
        List.iter
          (fun (_, s) ->
            Alcotest.(check string) (label ^ ": signers agree") (hex sg) (hex s))
          res.SNet.outputs;
        Alcotest.(check bool)
          (label ^ ": an independent verifier accepts it")
          true
          (V.verify_with_reference ~group_public_key:(El.serialize pk) ~msg sg))
      [
        ("fifo", Mpc_sim.Net.Fifo);
        ("reversed", Mpc_sim.Net.Reversed);
        ("shuffled", Mpc_sim.Net.Shuffled { window = 8 });
      ]

  let suites =
    [
      ( V.name,
        [
          Alcotest.test_case "DKG then sign, three schedules" `Quick
            t_dkg_then_sign;
        ] );
    ]
end
