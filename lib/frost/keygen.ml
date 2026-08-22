module Make (C : Mpc.Group.CIPHERSUITE) = struct
  module V = Mpc.Vss.Make (C)
  module Sh = V.S
  module M = Msg.Make (C)
  module Sess = Mpc.Session
  module Sc = C.Scalar
  module El = C.Element

  type config = {
    self : Sess.peer;
    peers : Sess.peer list;
    session : Sess.session_id;
    threshold : int;
    identifier : Sc.t;
    id_of_peer : Sess.peer -> Sc.t option;
  }

  type out = {
    identifier : Sc.t;
    signing_share : Sc.t;
    verification_share : El.t;
    group_public_key : El.t;
    commitment : V.t;
    verification_shares : (Sc.t * El.t) list;
  }

  type msg = M.t

  type t = {
    cfg : config;
    rand : Mpc.Rand.t;
    poly : Sh.poly option;
        (** {b secret}; dropped on every terminal transition *)
    slots : Sess.Slots.t;
    rnd : int;
    state : [ `Running | `Done | `Aborted of Sess.abort ];
  }

  let rounds = 2

  let create rand cfg =
    let n = List.length cfg.peers in
    if cfg.threshold < 1 || cfg.threshold > n then Error `Bad_threshold
    else if not (List.mem cfg.self cfg.peers) then
      Error (`Msg "Keygen: self is not in the participant set")
    else
      Ok
        {
          cfg;
          rand;
          poly = None;
          slots = Sess.Slots.create ~rounds ~peers:cfg.peers;
          rnd = 0;
          state = `Running;
        }

  let round t = t.rnd
  let status t = t.state
  let secrets_cleared t = t.poly = None
  let wipe t = match t.poly with Some p -> Sh.wipe p | None -> ()

  (* Atomic abort: the polynomial, every received share and every partial sum go. A
     partial sum is a linear function of other parties' secrets and partial sums from
     several aborted runs combine, so keeping one would be worse than keeping nothing. *)
  let clear t =
    wipe t;
    { t with poly = None; slots = Sess.Slots.wipe t.slots }

  let abort t ?(culprits = []) ?(detail = "") code =
    let a = { Sess.code; culprits; round = t.rnd; detail } in
    let t = clear t in
    ({ t with state = `Aborted a }, [ Sess.Aborted a ])

  let expected_from t =
    match t.state with
    | `Running -> Sess.Slots.missing t.slots ~round:t.rnd
    | _ -> []

  (* The proof of knowledge of a_i0.

     RFC 9591 leaves this construction open and publishes no vectors for it, so the
     choice is an interoperability decision rather than a specification one. This
     matches ZcashFoundation/frost byte for byte: their frost-core hashes
     SerializeScalar(id) || SerializeElement(phi_i0) || SerializeElement(R_i), and the
     ciphersuite's HDKG already prefixes the context string and the "dkg" domain
     separator.

     An earlier version also bound the session identifier in here. That is dropped
     deliberately: it bought replay protection the message header already provides --
     every message carries the session id and [admit] checks it before any
     cryptographic work is done -- at the price of interoperating with nothing. *)
  let pok_challenge ~id ~phi0 ~r =
    C.hdkg
      (String.concat "" [ Sc.serialize id; El.serialize phi0; El.serialize r ])

  let make_pok t ~poly =
    match Sc.random t.rand with
    | Error _ -> Error `Rng_failure
    | Ok k ->
        let r = El.scalar_mul_base k in
        let phi0 = El.scalar_mul_base (Sh.secret poly) in
        let c = pok_challenge ~id:t.cfg.identifier ~phi0 ~r in
        (* mu = k + a_0 * c; k is not needed again and is not retained. *)
        Ok (r, Sc.muladd (Sh.secret poly) c k)

  let verify_pok ~id ~commitment ~pok_r ~pok_mu =
    let phi0 = V.secret_commitment commitment in
    let c = pok_challenge ~id ~phi0 ~r:pok_r in
    (* R == mu*G - c*phi0. Both scalars are public. *)
    El.equal pok_r (El.sub (El.scalar_mul_base pok_mu) (El.scalar_mul c phi0))

  let store t ~round ~from payload =
    match Sess.Slots.put t.slots ~round ~from (M.encode_payload payload) with
    | `Stored slots -> `Stored { t with slots }
    | (`Duplicate | `Equivocation | `Unknown_peer | `Bad_round) as other ->
        other

  (* --- round 0 --- *)

  let start t =
    match Sc.random t.rand with
    | Error _ -> abort t ~detail:"randomness source failed" `Internal
    | Ok secret -> (
        match Sh.random t.rand ~degree:(t.cfg.threshold - 1) ~secret with
        | Error _ -> abort t ~detail:"randomness source failed" `Internal
        | Ok poly -> (
            let t = { t with poly = Some poly } in
            match make_pok t ~poly with
            | Error _ -> abort t ~detail:"randomness source failed" `Internal
            | Ok (pok_r, pok_mu) -> (
                let commitment = V.commit poly in
                let payload = M.Dkg_commit { commitment; pok_r; pok_mu } in
                (* Record our own contribution directly: a broadcast is not delivered back to
             its sender, and we must not treat ourselves as an outstanding peer. *)
                match store t ~round:0 ~from:t.cfg.self payload with
                | `Stored t ->
                    ( t,
                      [
                        Sess.Send
                          {
                            to_ = `All;
                            msg =
                              M.make ~session:t.cfg.session ~round:0
                                ~src:t.cfg.self payload;
                            private_ = false;
                          };
                      ] )
                | _ -> abort t `Internal)))

  let commitments_of t =
    List.filter_map
      (fun (p, raw) ->
        match (t.cfg.id_of_peer p, M.decode_payload raw) with
        | Some id, Ok (M.Dkg_commit { commitment; pok_r; pok_mu }) ->
            Some (p, id, commitment, pok_r, pok_mu)
        | _ -> None)
      (Sess.Slots.filled t.slots ~round:0)

  (* Every commitment is in: verify the proofs, then deal the shares. Mutually
     recursive with [finish] because an adversarial schedule can deliver every round-2
     share before we even enter round 2. *)
  let rec enter_round_1 t =
    let cs = commitments_of t in
    if List.length cs <> List.length t.cfg.peers then
      abort t ~detail:"a round-1 message was malformed" `Bad_message
    else
      let bad_length =
        List.filter_map
          (fun (p, _, commitment, _, _) ->
            if V.threshold commitment <> t.cfg.threshold then Some p else None)
          cs
      in
      if bad_length <> [] then
        abort t ~culprits:bad_length ~detail:"commitment of the wrong degree"
          `Bad_message
      else
        let bad_pok =
          List.filter_map
            (fun (p, id, commitment, pok_r, pok_mu) ->
              if verify_pok ~id ~commitment ~pok_r ~pok_mu then None else Some p)
            cs
        in
        if bad_pok <> [] then
          abort t ~culprits:bad_pok ~detail:"proof of knowledge does not verify"
            `Bad_proof
        else
          match t.poly with
          | None -> abort t `Internal
          | Some poly ->
              let t = { t with rnd = 1 } in
              (* Our own evaluation stays local; it is never transmitted. *)
              let own = M.Dkg_share { value = Sh.eval poly t.cfg.identifier } in
              let t =
                match store t ~round:1 ~from:t.cfg.self own with
                | `Stored t -> t
                | _ -> t
              in
              let sends =
                List.filter_map
                  (fun p ->
                    if p = t.cfg.self then None
                    else
                      Option.map
                        (fun id ->
                          Sess.Send
                            {
                              to_ = `Peer p;
                              msg =
                                M.make ~session:t.cfg.session ~round:1
                                  ~src:t.cfg.self ~dst:p
                                  (M.Dkg_share { value = Sh.eval poly id });
                              private_ = true;
                            })
                        (t.cfg.id_of_peer p))
                  t.cfg.peers
              in
              (* Shares can arrive before we finish round 1 -- under an adversarial
               schedule every one of them can. They are buffered, so on entering the
               round we must re-check completion or the session waits for messages that
               have already been delivered. The sends still go out: our peers need
               them. *)
              if Sess.Slots.complete t.slots ~round:1 then
                let t, evs = finish t in
                (t, sends @ evs)
              else (t, sends)

  (* --- finalize --- *)
  and finish t =
    let cs = commitments_of t in
    let shares =
      List.filter_map
        (fun (p, raw) ->
          match M.decode_payload raw with
          | Ok (M.Dkg_share { value }) -> Some (p, value)
          | _ -> None)
        (Sess.Slots.filled t.slots ~round:1)
    in
    if List.length shares <> List.length t.cfg.peers then
      abort t ~detail:"a round-2 message was malformed" `Bad_message
    else
      (* Check every received evaluation against its sender's public commitment. *)
      let bad =
        List.filter_map
          (fun (p, value) ->
            match List.find_opt (fun (q, _, _, _, _) -> q = p) cs with
            | None -> Some p
            | Some (_, _, commitment, _, _) -> (
                match
                  V.verify_share commitment { Sh.id = t.cfg.identifier; value }
                with
                | Ok () -> None
                | Error _ -> Some p))
          shares
      in
      if bad <> [] then
        abort t ~culprits:bad
          ~detail:"share does not match the sender's commitment" `Bad_share
      else
        (* s_i = sum of every evaluation received. Accumulated in a wipeable buffer:
           each partial sum is a linear function of other parties' secret polynomials,
           which is exactly the material an aborted run must not leave behind. *)
        let signing_share =
          let acc = Sc.Acc.create () in
          let term = Sc.Acc.create () in
          List.iter
            (fun (_, v) ->
              Sc.Acc.set term v;
              Sc.Acc.add ~dst:acc term)
            shares;
          let out = Sc.Acc.reveal acc in
          Sc.Acc.wipe acc;
          Sc.Acc.wipe term;
          out
        in
        match V.combine (List.map (fun (_, _, c, _, _) -> c) cs) with
        | Error _ -> abort t `Internal
        | Ok commitment ->
            let group_public_key = V.secret_commitment commitment in
            let verification_shares =
              List.filter_map
                (fun (_, id, _, _, _) ->
                  match V.participant_public_key [ commitment ] ~id with
                  | Ok e -> Some (id, e)
                  | Error _ -> None)
                cs
            in
            let out =
              {
                identifier = t.cfg.identifier;
                signing_share;
                verification_share = El.scalar_mul_base signing_share;
                group_public_key;
                commitment;
                verification_shares;
              }
            in
            let t = clear t in
            ({ t with state = `Done }, [ Sess.Output out ])

  let admit t (m : M.t) =
    if not (Eqaf.equal (m.M.session :> string) (t.cfg.session :> string)) then
      `Wrong_session
    else if m.M.src = t.cfg.self then `Unknown_peer
    else if not (List.mem m.M.src t.cfg.peers) then `Unknown_peer
    else if m.M.round < 0 || m.M.round >= rounds then `Wrong_round
    else `Ok

  let deliver t (m : M.t) =
    match m.M.payload with
    | M.Abort a ->
        let a = { a with Sess.round = t.rnd } in
        let t = clear t in
        ({ t with state = `Aborted a }, [ Sess.Aborted a ])
    | M.Dkg_commit _ -> (
        match store t ~round:0 ~from:m.M.src m.M.payload with
        | `Duplicate | `Unknown_peer | `Bad_round -> (t, [])
        | `Equivocation ->
            (* Equivocation in round 1 breaks the protocol outright: two commitments mean
           two different keys. Aborting is correct, not merely defensive. *)
            abort t ~culprits:[ m.M.src ]
              ~detail:"two different round-1 commitments" `Equivocation
        | `Stored t ->
            if t.rnd = 0 && Sess.Slots.complete t.slots ~round:0 then
              enter_round_1 t
            else (t, []))
    | M.Dkg_share { value } -> (
        match store t ~round:1 ~from:m.M.src m.M.payload with
        | `Duplicate | `Unknown_peer | `Bad_round -> (t, [])
        | `Equivocation ->
            abort t ~culprits:[ m.M.src ] ~detail:"two different round-2 shares"
              `Equivocation
        | `Stored t' -> (
            (* Check the evaluation against the sender's public commitment as soon as it
           arrives rather than at the end. The culprit is then unambiguous, and a
           dishonest dealer cannot hide behind a later failure. A share that arrives
           before we hold the sender's commitment is kept and checked on finalize. *)
            match
              List.find_opt
                (fun (q, _, _, _, _) -> q = m.M.src)
                (commitments_of t')
            with
            | Some (_, _, commitment, _, _)
              when V.verify_share commitment
                     { Sh.id = t'.cfg.identifier; value }
                   <> Ok () ->
                abort t' ~culprits:[ m.M.src ]
                  ~detail:"share does not match the sender's commitment"
                  `Bad_share
            | _ ->
                if t'.rnd = 1 && Sess.Slots.complete t'.slots ~round:1 then
                  finish t'
                else (t', [])))
    | M.Sign_commit _ | M.Sign_package _ | M.Sign_share _ | M.Sign_result _ ->
        (t, [])

  let settle t evs =
    let rec go t fuel evs acc =
      if fuel <= 0 then (t, List.rev acc)
      else
        match evs with
        | [] -> (t, List.rev acc)
        | Sess.Send { to_ = `Peer p; msg; _ } :: tl when p = t.cfg.self ->
            let t, more = deliver t msg in
            go t (fuel - 1) (tl @ more) acc
        | ev :: tl -> go t fuel tl (ev :: acc)
    in
    go t 64 evs []

  let step t input =
    match t.state with
    | `Done | `Aborted _ -> Ok (t, [])
    | `Running -> (
        try
          match input with
          | Sess.Start ->
              let t, evs = start t in
              Ok (settle t evs)
          | Sess.Cancel ->
              Ok (abort t ~detail:"cancelled by the driver" `Cancelled)
          | Sess.Timeout r ->
              if r <> t.rnd then Ok (t, [])
              else
                Ok
                  (abort t ~culprits:(expected_from t) ~detail:"round expired"
                     `Timeout)
          | Sess.Recv m -> (
              match admit t m with
              | `Wrong_session | `Unknown_peer | `Wrong_round -> Ok (t, [])
              | `Ok ->
                  let t, evs = deliver t m in
                  Ok (settle t evs))
        with e ->
          wipe t;
          let a =
            {
              Sess.code = `Internal;
              culprits = [];
              round = t.rnd;
              detail = Printexc.to_string e;
            }
          in
          Ok ({ t with poly = None; state = `Aborted a }, [ Sess.Aborted a ]))
end
