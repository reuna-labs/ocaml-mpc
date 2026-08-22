module Make (C : Mpc.Group.CIPHERSUITE) = struct
  module W = Mpc.Codec.W
  module R = Mpc.Codec.R
  module Sess = Mpc.Session
  module Sc = C.Scalar
  module El = C.Element

  type payload =
    | Dkg_commit of { commitment : El.t array; pok_r : El.t; pok_mu : Sc.t }
    | Dkg_share of { value : Sc.t }
    | Sign_commit of { hiding : El.t; binding : El.t }
    | Sign_package of {
        commitments : (Sc.t * (El.t * El.t)) list;
        msg : string;
      }
    | Sign_share of { z : Sc.t }
    | Sign_result of { signature : string }
    | Abort of Sess.abort

  type t = {
    version : int;
    suite : int;
    session : Sess.session_id;
    round : int;
    src : Sess.peer;
    dst : Sess.peer option;
    payload : payload;
  }

  let version = 1
  let protocol = 1 (* FROST *)
  let header_len = 4 + 32 + 2 + 2 + 4

  let make ~session ~round ~src ?dst payload =
    { version; suite = C.suite_tag; session; round; src; dst; payload }

  let kind = function
    | Dkg_commit _ -> 0x10
    | Dkg_share _ -> 0x11
    | Sign_commit _ -> 0x20
    | Sign_package _ -> 0x21
    | Sign_share _ -> 0x22
    | Sign_result _ -> 0x23
    | Abort _ -> 0x30

  let is_private = function Dkg_share _ -> true | _ -> false

  let abort_code_to_int : Sess.abort_code -> int = function
    | `Timeout -> 1
    | `Bad_message -> 2
    | `Bad_proof -> 3
    | `Bad_share -> 4
    | `Equivocation -> 5
    | `Cancelled -> 6
    | `Nonce_already_used -> 7
    | `Internal -> 8

  let abort_code_of_int : int -> (Sess.abort_code, Mpc.Error.t) result =
    function
    | 1 -> Ok `Timeout
    | 2 -> Ok `Bad_message
    | 3 -> Ok `Bad_proof
    | 4 -> Ok `Bad_share
    | 5 -> Ok `Equivocation
    | 6 -> Ok `Cancelled
    | 7 -> Ok `Nonce_already_used
    | 8 -> Ok `Internal
    | _ -> Error `Invalid_format

  let write_payload w = function
    | Dkg_commit { commitment; pok_r; pok_mu } ->
        W.u16 w (Array.length commitment);
        Array.iter (fun p -> W.fixed w ~len:C.ne (El.serialize p)) commitment;
        W.fixed w ~len:C.ne (El.serialize pok_r);
        W.fixed w ~len:C.ns (Sc.serialize pok_mu)
    | Dkg_share { value } -> W.fixed w ~len:C.ns (Sc.serialize value)
    | Sign_commit { hiding; binding } ->
        W.fixed w ~len:C.ne (El.serialize hiding);
        W.fixed w ~len:C.ne (El.serialize binding)
    | Sign_package { commitments; msg } ->
        W.vector16 w
          (fun w (id, (h, b)) ->
            W.fixed w ~len:C.ns (Sc.serialize id);
            W.fixed w ~len:C.ne (El.serialize h);
            W.fixed w ~len:C.ne (El.serialize b))
          commitments;
        W.str32 w msg
    | Sign_share { z } -> W.fixed w ~len:C.ns (Sc.serialize z)
    | Sign_result { signature } -> W.str16 w signature
    | Abort a ->
        W.u16 w (abort_code_to_int a.Sess.code);
        W.u32 w (Int32.of_int a.Sess.round);
        W.vector16 w (fun w p -> W.u16 w (Sess.peer_to_int p)) a.Sess.culprits;
        W.str16 w a.Sess.detail

  let encode_payload p =
    let w = W.create () in
    W.u8 w (kind p);
    write_payload w p;
    W.contents w

  let element r =
    match El.deserialize (R.fixed r C.ne) with
    | Ok p -> p
    | Error e ->
        R.fail
          (match e with
          | `Invalid_length -> `Invalid_length
          | _ -> `Invalid_format)

  let scalar r =
    match Sc.deserialize (R.fixed r C.ns) with
    | Ok s -> s
    | Error _ -> R.fail `Invalid_format

  let peer_of_int n =
    match Sess.peer n with Ok p -> p | Error _ -> R.fail `Invalid_format

  let read_payload r = function
    | 0x10 ->
        let n = R.count16 r in
        if n = 0 then R.fail `Invalid_format;
        let commitment = Array.init n (fun _ -> element r) in
        let pok_r = element r in
        let pok_mu = scalar r in
        Dkg_commit { commitment; pok_r; pok_mu }
    | 0x11 -> Dkg_share { value = scalar r }
    | 0x20 ->
        let hiding = element r in
        let binding = element r in
        Sign_commit { hiding; binding }
    | 0x21 ->
        let commitments =
          R.vector16 r (fun r ->
              let id = scalar r in
              let h = element r in
              let b = element r in
              (id, (h, b)))
        in
        let msg = R.str32 r in
        Sign_package { commitments; msg }
    | 0x22 -> Sign_share { z = scalar r }
    | 0x23 -> Sign_result { signature = R.str16 r }
    | 0x30 ->
        let code =
          match abort_code_of_int (R.u16 r) with
          | Ok c -> c
          | Error _ -> R.fail `Invalid_format
        in
        let round = Int32.to_int (R.u32 r) in
        let culprits = R.vector16 r (fun r -> peer_of_int (R.u16 r)) in
        let detail = R.str16 r in
        Abort { Sess.code; round; culprits; detail }
    | _ -> R.fail `Invalid_format

  let decode_payload s =
    match
      R.run ~exact:true
        (fun r ->
          let k = R.u8 r in
          read_payload r k)
        s
    with
    | Error e -> Error (e :> Mpc.Error.t)
    | Ok p -> Ok p

  let write_header w m =
    W.u8 w m.version;
    W.u8 w protocol;
    W.u8 w m.suite;
    W.u8 w (kind m.payload);
    W.fixed w ~len:32 (m.session :> string);
    W.u16 w (Sess.peer_to_int m.src);
    W.u16 w (match m.dst with None -> 0 | Some p -> Sess.peer_to_int p);
    W.u32 w (Int32.of_int m.round)

  let encode ?seal m =
    match (is_private m.payload, seal, m.dst) with
    | true, None, _ -> Error `Unsealed_private_payload
    | true, Some _, None ->
        (* A private payload has no meaningful recipient to seal to. *)
        Error `Unsealed_private_payload
    | _ ->
        let body = W.to_string write_payload m.payload in
        let body =
          match (is_private m.payload, seal, m.dst) with
          | true, Some f, Some dst -> f ~peer:dst body
          | _ -> body
        in
        let w = W.create () in
        write_header w m;
        W.str32 w body;
        Ok (W.contents w)

  let read_header r =
    let v = R.u8 r in
    let proto = R.u8 r in
    let suite = R.u8 r in
    let k = R.u8 r in
    let session = R.fixed r 32 in
    let src = peer_of_int (R.u16 r) in
    let dst_raw = R.u16 r in
    let round = Int32.to_int (R.u32 r) in
    if v <> version || proto <> protocol || suite <> C.suite_tag then
      R.fail `Invalid_format;
    if round < 0 then R.fail `Invalid_format;
    let dst = if dst_raw = 0 then None else Some (peer_of_int dst_raw) in
    let session =
      match Sess.session_id session with
      | Ok s -> s
      | Error _ -> R.fail `Invalid_length
    in
    (v, suite, session, round, src, dst, k)

  let decode_header s =
    if String.length s < header_len then
      Error (`Eof (header_len - String.length s))
    else
      match R.run ~exact:false (fun r -> read_header r) s with
      | Error e -> Error (e :> Mpc.Error.t)
      | Ok (v, suite, session, round, src, dst, _) ->
          Ok (v, suite, session, round, src, dst)

  let decode ?unseal s =
    match
      R.run ~exact:true
        (fun r ->
          let v, suite, session, round, src, dst, k = read_header r in
          let body = R.str32 r in
          (v, suite, session, round, src, dst, k, body))
        s
    with
    | Error e -> Error (e :> Mpc.Error.t)
    | Ok (version, suite, session, round, src, dst, k, body) -> (
        let private_ = k = 0x11 in
        let body =
          match (private_, unseal, dst) with
          (* The counterpart is the SOURCE here, mirroring [encode], which seals to the
             destination. Naming the destination on both sides would have each end
             derive a key for the pair (itself, itself), and nothing would open. A
             private payload must also be point-to-point, hence requiring [dst]. *)
          | true, Some f, Some _ -> f ~peer:src body
          | true, None, _ -> Error `Unsealed_private_payload
          | true, Some _, None -> Error `Unsealed_private_payload
          | false, _, _ -> Ok body
        in
        match body with
        | Error e -> Error e
        | Ok body -> (
            match R.run ~exact:true (fun r -> read_payload r k) body with
            | Error e -> Error (e :> Mpc.Error.t)
            | Ok payload ->
                Ok { version; suite; session; round; src; dst; payload }))
end
