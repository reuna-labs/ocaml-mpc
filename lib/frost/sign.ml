module Make (C : Mpc.Group.CIPHERSUITE) = struct
  module F = Core.Make (C)
  module M = Msg.Make (C)
  module Sess = Mpc.Session
  module Sc = C.Scalar
  module El = C.Element

  type config = {
    self : Sess.peer;
    coordinator : Sess.peer;
    signers : Sess.peer list;
    session : Sess.session_id;
    identifier : Sc.t;
    signing_share : Sc.t option;
    group_public_key : El.t;
    verification_shares : (Sc.t * El.t) list;
    id_of_peer : Sess.peer -> Sc.t option;
    msg : string;
  }

  type out = string
  type msg = M.t

  type part =
    | P_absent  (** this node holds no signing share *)
    | P_idle
    | P_committed of { nonce : Mpc.Secret.t; commitment : F.E.commitment }
    | P_done

  type coord =
    | C_absent
    | C_collecting
    | C_awaiting of {
        cl : F.E.commitment_list;
        bf : (Sc.t * Sc.t) list;
        gc : El.t;
      }
    | C_done

  (* Every field is immutable. The single mutable thing a session owns is the
     [Mpc.Secret.t] holding the nonce, and that is deliberate: it is what a retained
     copy of an older state value shares with a newer one, and therefore what makes
     replaying a round-2 message fail instead of producing a second signature share. *)
  type t = {
    cfg : config;
    rand : Mpc.Rand.t;
    slots : Sess.Slots.t;
    part : part;
    coord : coord;
    rnd : int;
    state : [ `Running | `Done | `Aborted of Sess.abort ];
  }

  let rounds = 2

  let create rand cfg =
    if not (List.mem cfg.self cfg.signers || cfg.self = cfg.coordinator) then
      Error (`Msg "Sign: self is neither a signer nor the coordinator")
    else if cfg.signers = [] then Error `Bad_threshold
    else
      Ok
        {
          cfg;
          rand;
          slots = Sess.Slots.create ~rounds ~peers:cfg.signers;
          part = (if cfg.signing_share = None then P_absent else P_idle);
          coord =
            (if cfg.self = cfg.coordinator then C_collecting else C_absent);
          rnd = 0;
          state = `Running;
        }

  let round t = t.rnd
  let status t = t.state

  (* The only erasure that actually erases: the nonce cell is mutable bytes. *)
  let wipe t =
    match t.part with
    | P_committed { nonce; _ } -> Mpc.Secret.wipe nonce
    | _ -> ()

  let nonce_burned t =
    match t.part with
    | P_committed { nonce; _ } -> Mpc.Secret.wiped nonce
    | P_done -> true
    | P_absent | P_idle -> false

  (* Terminal transitions also drop references to received payloads. Dropping a
     reference bounds a secret's lifetime; it does not overwrite an immutable string. *)
  let clear t =
    wipe t;
    { t with slots = Sess.Slots.wipe t.slots }

  (* Abort is terminal, never a rollback: retrying a round while reusing a nonce is the
     hazard the whole design exists to prevent. It burns the nonce first and
     unconditionally. A retry is a new session with a new identifier. *)
  let abort t ?(culprits = []) ?(detail = "") code =
    let a = { Sess.code; culprits; round = t.rnd; detail } in
    let t = clear t in
    ({ t with state = `Aborted a }, [ Sess.Aborted a ])

  let expected_from t =
    match t.state with
    | `Running -> (
        match (t.coord, t.part) with
        | (C_collecting | C_awaiting _), _ ->
            Sess.Slots.missing t.slots ~round:t.rnd
        | _, P_committed _ -> [ t.cfg.coordinator ]
        | _ -> [])
    | `Done | `Aborted _ -> []

  let store_nonce (n : F.nonces) =
    Mpc.Secret.of_string (Sc.serialize n.F.hiding ^ Sc.serialize n.F.binding)

  (* Reading and burning are one operation: there is no way to obtain the nonce without
     erasing it, so no code path can produce two signature shares from one commitment. *)
  let take_and_burn cell =
    match Mpc.Secret.get cell with
    | None -> Error `Nonce_already_used
    | Some s -> (
        Mpc.Secret.wipe cell;
        if String.length s <> 2 * C.ns then Error `Internal
        else
          match
            ( Sc.deserialize (String.sub s 0 C.ns),
              Sc.deserialize (String.sub s C.ns C.ns) )
          with
          | Ok hiding, Ok binding -> Ok { F.hiding; binding }
          | _ -> Error `Internal)

  (* Compare payloads, not framed messages: the header carries a round and a
     destination that are not part of what a peer committed to, and encoding a whole
     message would need a seal for private payloads. *)
  let raw_of (m : M.t) = Some (M.encode_payload m.M.payload)

  (* --- round 0: commit --- *)

  let start t =
    match t.cfg.signing_share with
    | None -> (t, [])
    | Some share -> (
        match F.commit t.rand ~secret:share with
        | Error _ -> abort t ~detail:"randomness source failed" `Internal
        | Ok (nonces, commitment) ->
            let t =
              {
                t with
                part = P_committed { nonce = store_nonce nonces; commitment };
              }
            in
            ( t,
              [
                Sess.Send
                  {
                    to_ = `Peer t.cfg.coordinator;
                    msg =
                      M.make ~session:t.cfg.session ~round:0 ~src:t.cfg.self
                        ~dst:t.cfg.coordinator
                        (M.Sign_commit
                           {
                             hiding = commitment.F.E.hiding;
                             binding = commitment.F.E.binding;
                           });
                    private_ = false;
                  };
              ] ))

  (* --- coordinator: assemble the signing package --- *)

  let build_package t =
    let entries =
      List.filter_map
        (fun (p, payload) ->
          match (t.cfg.id_of_peer p, M.decode_payload payload) with
          | Some id, Ok (M.Sign_commit { hiding; binding }) ->
              Some (id, { F.E.hiding; binding })
          | _ -> None)
        (Sess.Slots.filled t.slots ~round:0)
    in
    if List.length entries <> List.length t.cfg.signers then Error `Bad_message
    else
      match F.E.commitment_list entries with
      | Error _ -> Error `Bad_message
      | Ok cl ->
          let bf =
            F.binding_factors ~group_public_key:t.cfg.group_public_key
              ~commitment_list:cl ~msg:t.cfg.msg
          in
          Ok (cl, bf, F.group_commitment ~commitment_list:cl ~binding_factors:bf)

  let package_payload t cl =
    M.Sign_package
      {
        commitments =
          List.map
            (fun (id, (c : F.E.commitment)) ->
              (id, (c.F.E.hiding, c.F.E.binding)))
            cl;
        msg = t.cfg.msg;
      }

  (* --- participant: sign, burning the nonce before the share leaves --- *)

  let handle_package t commitments pkg_msg =
    if not (String.equal pkg_msg t.cfg.msg) then
      abort t ~culprits:[ t.cfg.coordinator ]
        ~detail:"coordinator proposed a different message" `Bad_message
    else
      match t.part with
      | P_absent | P_idle | P_done -> (t, [])
      | P_committed { nonce; commitment } -> (
          match
            F.E.commitment_list
              (List.map
                 (fun (id, (h, b)) -> (id, { F.E.hiding = h; binding = b }))
                 commitments)
          with
          | Error _ ->
              abort t ~culprits:[ t.cfg.coordinator ]
                ~detail:"malformed commitment list" `Bad_message
          | Ok cl -> (
              match
                List.find_opt (fun (id, _) -> Sc.equal id t.cfg.identifier) cl
              with
              | None ->
                  abort t ~culprits:[ t.cfg.coordinator ]
                    ~detail:"our identifier is absent from the commitment list"
                    `Bad_message
              | Some (_, (mine : F.E.commitment)) -> (
                  if
                    (* Refuse to sign against anyone else's idea of our own commitment: without
               this a coordinator could have us sign under a commitment we never made. *)
                    not
                      (El.equal mine.F.E.hiding commitment.F.E.hiding
                      && El.equal mine.F.E.binding commitment.F.E.binding)
                  then
                    abort t ~culprits:[ t.cfg.coordinator ]
                      ~detail:
                        "commitment list does not match the commitment we sent"
                      `Bad_message
                  else
                    match take_and_burn nonce with
                    | Error `Nonce_already_used ->
                        abort t
                          ~detail:
                            "a signature share was already produced for this \
                             session"
                          `Nonce_already_used
                    | Error _ -> abort t `Internal
                    | Ok nonces -> (
                        match t.cfg.signing_share with
                        | None -> abort t `Internal
                        | Some share -> (
                            match
                              F.sign ~id:t.cfg.identifier ~share
                                ~group_public_key:t.cfg.group_public_key ~nonces
                                ~msg:t.cfg.msg ~commitment_list:cl
                            with
                            | Error _ -> abort t `Internal
                            | Ok z ->
                                ( { t with part = P_done },
                                  [
                                    Sess.Send
                                      {
                                        to_ = `Peer t.cfg.coordinator;
                                        msg =
                                          M.make ~session:t.cfg.session ~round:1
                                            ~src:t.cfg.self
                                            ~dst:t.cfg.coordinator
                                            (M.Sign_share { z });
                                        private_ = false;
                                      };
                                  ] ))))))

  (* --- coordinator: aggregate, naming the culprit when it does not verify --- *)

  let aggregate t cl bf gc =
    let shares =
      List.filter_map
        (fun (p, payload) ->
          match (t.cfg.id_of_peer p, M.decode_payload payload) with
          | Some id, Ok (M.Sign_share { z }) -> Some (p, id, z)
          | _ -> None)
        (Sess.Slots.filled t.slots ~round:1)
    in
    if List.length shares <> List.length t.cfg.signers then
      abort t ~detail:"missing or malformed signature shares" `Bad_message
    else
      let sg =
        F.aggregate ~group_commitment:gc (List.map (fun (_, _, z) -> z) shares)
      in
      if F.verify ~group_public_key:t.cfg.group_public_key ~msg:t.cfg.msg sg
      then begin
        (* Broadcast the aggregate. Without it a participant that has sent its share has
           no terminal state and simply waits; with it, every signer learns the result
           and verifies it for itself rather than taking the coordinator's word. *)
        let announce =
          Sess.Send
            {
              to_ = `All;
              msg =
                M.make ~session:t.cfg.session ~round:1 ~src:t.cfg.self
                  (M.Sign_result { signature = sg });
              private_ = false;
            }
        in
        let t = clear t in
        ({ t with coord = C_done; state = `Done }, [ announce; Sess.Output sg ])
      end
      else
        (* FROST gives identifiable abort here for free: check each contribution rather
           than return an opaque invalid signature. *)
        let culprits =
          List.filter_map
            (fun (p, id, z) ->
              match
                List.find_opt
                  (fun (i, _) -> Sc.equal i id)
                  t.cfg.verification_shares
              with
              | None -> Some p
              | Some (_, vs) -> (
                  match
                    F.verify_signature_share ~id ~verification_share:vs
                      ~sig_share:z ~commitment_list:cl ~binding_factors:bf
                      ~group_public_key:t.cfg.group_public_key ~msg:t.cfg.msg
                  with
                  | Ok () -> None
                  | Error _ -> Some p))
            shares
        in
        abort t ~culprits ~detail:"aggregated signature does not verify"
          `Bad_share

  (* --- admission, cheapest checks first: a malformed message must cost comparisons,
         not a scalar multiplication --- *)

  let admit t (m : M.t) =
    if not (Eqaf.equal (m.M.session :> string) (t.cfg.session :> string)) then
      `Wrong_session
    else if m.M.src = t.cfg.self then `Unknown_peer
    else if not (List.mem m.M.src t.cfg.signers || m.M.src = t.cfg.coordinator)
    then `Unknown_peer
    else if m.M.round < 0 || m.M.round >= rounds then `Wrong_round
    else `Ok

  let deliver t (m : M.t) =
    match m.M.payload with
    | M.Abort a ->
        let a = { a with Sess.round = t.rnd } in
        let t = clear t in
        ({ t with state = `Aborted a }, [ Sess.Aborted a ])
    | M.Sign_commit _ -> (
        match (t.coord, raw_of m) with
        | C_collecting, Some raw -> (
            match Sess.Slots.put t.slots ~round:0 ~from:m.M.src raw with
            | `Duplicate | `Unknown_peer | `Bad_round -> (t, [])
            | `Equivocation ->
                abort t ~culprits:[ m.M.src ]
                  ~detail:"two different commitments for round 0" `Equivocation
            | `Stored slots -> (
                let t = { t with slots } in
                if not (Sess.Slots.complete t.slots ~round:0) then (t, [])
                else
                  match build_package t with
                  | Error _ ->
                      abort t ~detail:"could not assemble the signing package"
                        `Bad_message
                  | Ok (cl, bf, gc) ->
                      let t =
                        { t with coord = C_awaiting { cl; bf; gc }; rnd = 1 }
                      in
                      let payload = package_payload t cl in
                      let out =
                        M.make ~session:t.cfg.session ~round:1 ~src:t.cfg.self
                          payload
                      in
                      (* Apply the package locally too: the coordinator is commonly also a
                 signer, and a broadcast is not delivered back to its sender. *)
                      let t, local =
                        match payload with
                        | M.Sign_package { commitments; msg } ->
                            handle_package t commitments msg
                        | _ -> (t, [])
                      in
                      ( t,
                        Sess.Send { to_ = `All; msg = out; private_ = false }
                        :: local )))
        | _ -> (t, []))
    | M.Sign_package { commitments; msg } ->
        if m.M.src <> t.cfg.coordinator then (t, [])
        else handle_package { t with rnd = max t.rnd 1 } commitments msg
    | M.Sign_share _ -> (
        match (t.coord, raw_of m) with
        | C_awaiting { cl; bf; gc }, Some raw -> (
            match Sess.Slots.put t.slots ~round:1 ~from:m.M.src raw with
            | `Duplicate | `Unknown_peer | `Bad_round -> (t, [])
            | `Equivocation ->
                abort t ~culprits:[ m.M.src ]
                  ~detail:"two different signature shares" `Equivocation
            | `Stored slots ->
                let t = { t with slots } in
                if Sess.Slots.complete t.slots ~round:1 then
                  aggregate t cl bf gc
                else (t, []))
        | _ -> (t, []))
    | M.Sign_result { signature } ->
        if m.M.src <> t.cfg.coordinator then (t, [])
        else if
          F.verify ~group_public_key:t.cfg.group_public_key ~msg:t.cfg.msg
            signature
        then
          let t = clear t in
          ({ t with state = `Done }, [ Sess.Output signature ])
        else
          (* The coordinator announced something that does not verify. That is its
             fault, and it is nameable. *)
          abort t ~culprits:[ t.cfg.coordinator ]
            ~detail:"announced signature does not verify" `Bad_share
    (* Key-generation payloads carry no signing authority. Dropping a misrouted message
       is right: treating it as an abort would let one confused peer stall a healthy
       round. *)
    | M.Dkg_commit _ | M.Dkg_share _ -> (t, [])

  (* A node is commonly both a signer and the coordinator, and its own messages are
     addressed to itself. The transport never carries those, and [admit] rejects
     src = self so that no peer can impersonate us, so the session feeds them back
     internally and drops them from the emitted events. The fuel bound is a backstop:
     each local delivery advances a two-round protocol and cannot legitimately loop. *)
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
    go t 16 evs []

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
              (* A timeout for a round already left behind is not an error: the driver has
             no way to know the round advanced concurrently. *)
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
          (* Defence in depth: no exceptional path may leave a live nonce behind. *)
          wipe t;
          let a =
            {
              Sess.code = `Internal;
              culprits = [];
              round = t.rnd;
              detail = Printexc.to_string e;
            }
          in
          Ok ({ t with state = `Aborted a }, [ Sess.Aborted a ]))
end
