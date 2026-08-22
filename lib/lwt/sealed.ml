module Make (A : Mirage_crypto.AEAD) = struct
  (* 96-bit nonce: the size every AEAD in mirage-crypto accepts, and the one GCM is
     specified for. Drawn fresh per payload rather than derived, so that a repeated
     session identifier -- a caller error -- cannot become a repeated nonce, which for
     GCM would be catastrophic rather than merely wasteful. *)
  let nonce_size = 12
  let overhead = nonce_size + A.tag_size

  type t = {
    self : Mpc.Session.peer;
    rand : Mpc.Rand.t;
    key_of_peer : Mpc.Session.peer -> A.key option;
  }

  let v ~self ~rand ~key_of_peer = { self; rand; key_of_peer }

  (* Bind both endpoints and the direction of travel. Binding only the recipient would
     let a payload be reflected back at its sender; binding neither would let it be
     replayed at a different participant. *)
  let adata ~from ~to_ =
    Printf.sprintf "mpc-sealed-v1|from=%d|to=%d"
      (Mpc.Session.peer_to_int from)
      (Mpc.Session.peer_to_int to_)

  let key t peer =
    match t.key_of_peer peer with
    | None ->
        failwith
          (Printf.sprintf "Mpc_lwt.Sealed: no shared key for peer %d"
             (Mpc.Session.peer_to_int peer))
    | Some k -> k

  let seal t ~peer payload =
    let k = key t peer in
    match Mpc.Rand.bytes t.rand nonce_size with
    | Error _ -> failwith "Mpc_lwt.Sealed: randomness source failed"
    | Ok nonce ->
        nonce
        ^ A.authenticate_encrypt ~key:k ~nonce
            ~adata:(adata ~from:t.self ~to_:peer)
            payload

  let unseal t ~peer sealed =
    if String.length sealed < nonce_size + A.tag_size then Error `Invalid_length
    else
      match t.key_of_peer peer with
      | None -> Error (`Msg "no shared key for this peer")
      | Some k -> (
          let nonce = String.sub sealed 0 nonce_size in
          let body =
            String.sub sealed nonce_size (String.length sealed - nonce_size)
          in
          match
            A.authenticate_decrypt ~key:k ~nonce
              ~adata:(adata ~from:peer ~to_:t.self)
              body
          with
          | Some plain -> Ok plain
          | None -> Error (`Msg "sealed payload failed authentication"))
end
