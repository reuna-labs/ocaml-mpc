(** End-to-end over real Unix sockets.

    Everything above this file runs in a simulator with an in-memory network.
    This is the test that says the transport is real: three processes' worth of
    sessions, a full mesh of actual sockets, length-prefixed framing over a byte
    stream that fragments where it likes, a distributed key generation with its
    private shares sealed, and then a threshold signature that a stock RFC 8032
    verifier accepts. *)

open Lwt.Infix
module Suite = Mpc_ed25519.Suite
module Sc = Suite.Scalar
module El = Suite.Element
module Sess = Mpc.Session
module Msg = Mpc_frost.Msg.Make (Suite)
module Keygen = Mpc_frost.Keygen.Make (Suite)
module Sign = Mpc_frost.Sign.Make (Suite)

(* Pass the defining path to the functor rather than an alias: [Mirage_flow.S] declares
   [write_error] as a private row, and re-ascribing through an alias makes that row
   opaque, after which the module no longer satisfies the signature. *)
module KDriver = Mpc_lwt.Driver.Make (Keygen) (Mirage_flow_unix.Fd)
module SDriver = Mpc_lwt.Driver.Make (Sign) (Mirage_flow_unix.Fd)
module Flow = Mirage_flow_unix.Fd
module Seal = Mpc_lwt.Sealed.Make (Mirage_crypto.AES.GCM)

let peer n = Result.get_ok (Sess.peer n)
let id n = Result.get_ok (Sc.of_int n)

let rand_of_seed seed =
  let g =
    Mirage_crypto_rng.create ~strict:true ~seed
      (module Mirage_crypto_rng.Hmac_drbg (Digestif.SHA256))
  in
  Mpc.Rand.v (fun n -> Mirage_crypto_rng.generate ~g n)

(* A pairwise secret both ends can derive without a key exchange. This is a test
   fixture, not a key agreement: a deployment derives these from a real handshake, or
   uses TLS and no seal at all. *)
let pair_secret a b =
  let lo = min a b and hi = max a b in
  Digestif.SHA256.(
    to_raw_string (digest_string (Printf.sprintf "mpc-test-pair|%d|%d" lo hi)))

let seal_for self =
  Seal.v ~self
    ~rand:(rand_of_seed (Printf.sprintf "seal-%d" (Sess.peer_to_int self)))
    ~key_of_peer:(fun p ->
      Some
        (Mirage_crypto.AES.GCM.of_secret
           (pair_secret (Sess.peer_to_int self) (Sess.peer_to_int p))))

let wire_keygen self : KDriver.wire =
  let s = seal_for self in
  {
    KDriver.encode =
      (fun m -> Msg.encode ~seal:(fun ~peer p -> Seal.seal s ~peer p) m);
    decode =
      (fun b -> Msg.decode ~unseal:(fun ~peer p -> Seal.unseal s ~peer p) b);
  }

let wire_sign _self : SDriver.wire =
  (* Signing carries no private payloads: commitments and signature shares are public
     by construction. No seal is required, and requiring one anyway would be cargo
     cult. *)
  { SDriver.encode = (fun m -> Msg.encode m); decode = (fun b -> Msg.decode b) }

let sleep_ns ns = Lwt_unix.sleep (Int64.to_float ns /. 1e9)
let timeout_ns = 15_000_000_000L
let id_of_peer p = Some (id (Sess.peer_to_int p))

let socket_dir =
  lazy
    (let d =
       Filename.concat
         (Filename.get_temp_dir_name ())
         (Printf.sprintf "mpc-test-%d" (Unix.getpid ()))
     in
     (try Unix.mkdir d 0o700 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
     d)

(* Unix domain sockets rather than TCP: no port allocation, no chance of colliding
   with something else on the machine, and the framing and flow code under test is
   identical either way. *)
let addr phase n =
  Mpc_unix.Unix_socket
    (Filename.concat (Lazy.force socket_dir)
       (Printf.sprintf "%s-p%d.sock" phase n))

(* A fresh mesh per phase. The driver owns a flow's byte stream for the lifetime of one
   session and the stream carries no session demultiplexing, so reusing the DKG's flows
   for signing would have the two sessions' readers split bytes between them. *)
let mesh ~phase ~self ~members =
  let peers = List.filter (fun p -> p <> self) members in
  Mpc_unix.Mesh.connect ~self
    ~listen:(addr phase (Sess.peer_to_int self))
    ~peers:(List.map (fun p -> (p, addr phase (Sess.peer_to_int p))) peers)
    ~connect_timeout_s:10. ()

let close_flows flows = Lwt_list.iter_p (fun (_, f) -> Flow.close f) flows

(* --- one node's whole job: mesh, DKG, then sign --- *)

let node ~self ~all ~signers ~coordinator ~msg =
  mesh ~phase:"dkg" ~self ~members:all >>= function
  | Error (`Msg m) -> Lwt.return (Error (Printf.sprintf "mesh(dkg): %s" m))
  | Ok flows -> (
      let session =
        Sess.derive_session_id ~domain:"e2e-dkg" ~group_public_key:""
          ~participants:all ~context:"2-of-3" ~nonce:(String.make 32 '\021')
      in
      let cfg =
        {
          Keygen.self;
          peers = all;
          session;
          threshold = 2;
          identifier = id (Sess.peer_to_int self);
          id_of_peer;
        }
      in
      let m =
        Result.get_ok
          (Keygen.create
             (rand_of_seed (Printf.sprintf "dkg-%d" (Sess.peer_to_int self)))
             cfg)
      in
      KDriver.run ~round_timeout_ns:timeout_ns ~sleep_ns
        ~wire:(wire_keygen self) ~peers:flows m
      >>= fun dkg_result ->
      close_flows flows >>= fun () ->
      match dkg_result with
      | Error e ->
          Lwt.return (Error (Format.asprintf "dkg: %a" KDriver.pp_error e))
      | Ok (out : Keygen.out) -> (
          if not (List.mem self signers) then Lwt.return (Ok (out, None))
          else
            mesh ~phase:"sign" ~self ~members:signers >>= function
            | Error (`Msg m) ->
                Lwt.return (Error (Printf.sprintf "mesh(sign): %s" m))
            | Ok sflows -> (
                let sign_session =
                  Sess.derive_session_id ~domain:"e2e-sign"
                    ~group_public_key:(El.serialize out.Keygen.group_public_key)
                    ~participants:signers ~context:msg
                    ~nonce:(String.make 32 '\022')
                in
                let scfg =
                  {
                    Sign.self;
                    coordinator;
                    signers;
                    session = sign_session;
                    identifier = out.Keygen.identifier;
                    signing_share = Some out.Keygen.signing_share;
                    group_public_key = out.Keygen.group_public_key;
                    verification_shares = out.Keygen.verification_shares;
                    id_of_peer;
                    msg;
                  }
                in
                let sm =
                  Result.get_ok
                    (Sign.create
                       (rand_of_seed
                          (Printf.sprintf "sign-%d" (Sess.peer_to_int self)))
                       scfg)
                in
                SDriver.run ~round_timeout_ns:timeout_ns ~sleep_ns
                  ~wire:(wire_sign self) ~peers:sflows sm
                >>= fun r ->
                close_flows sflows >|= fun () ->
                match r with
                | Ok sg -> Ok (out, Some sg)
                | Error `No_output ->
                    (* A participant that is not the coordinator never sees the aggregate. *)
                    Ok (out, None)
                | Error e ->
                    Error (Format.asprintf "sign: %a" SDriver.pp_error e))))

let run_cluster ~n ~msg =
  let all = List.init n (fun i -> peer (i + 1)) in
  let signers = [ peer 1; peer 2 ] in
  let coordinator = peer 1 in
  Lwt_list.map_p (fun self -> node ~self ~all ~signers ~coordinator ~msg) all

(* --- tests --- *)

let t_dkg_and_sign _ () =
  let msg = "signed over real sockets" in
  run_cluster ~n:3 ~msg >|= fun results ->
  List.iteri
    (fun i r ->
      match r with
      | Error e -> Alcotest.failf "node %d failed: %s" (i + 1) e
      | Ok _ -> ())
    results;
  let outs =
    List.map (function Ok (o, s) -> (o, s) | Error _ -> assert false) results
  in
  (* Every node agreed on the group key. *)
  let pk = (fst (List.hd outs)).Keygen.group_public_key in
  List.iter
    (fun (o, _) ->
      Alcotest.(check string)
        "same group public key"
        (Ohex.encode (El.serialize pk))
        (Ohex.encode (El.serialize o.Keygen.group_public_key)))
    outs;
  (* Every signer ends up with the aggregate -- the coordinator by construction, the
     others because it broadcasts the result and they verify it themselves. The node
     that did not sign has none. *)
  let sigs = List.filter_map snd outs in
  Alcotest.(check int) "each signer obtained the signature" 2 (List.length sigs);
  List.iter
    (fun sg ->
      Alcotest.(check string)
        "and they all agree"
        (Ohex.encode (List.hd sigs))
        (Ohex.encode sg))
    sigs;
  let ed_pub =
    Result.get_ok (Mirage_crypto_ec.Ed25519.pub_of_octets (El.serialize pk))
  in
  Alcotest.(check bool)
    "RFC 8032 verifier accepts it" true
    (Mirage_crypto_ec.Ed25519.verify ~key:ed_pub (List.hd sigs) ~msg)

let t_seal_roundtrip _ () =
  (* Two endpoints, because the seal binds the direction of travel: what A sealed for B
     opens at B and nowhere else -- not at a third party, and not back at A. *)
  let a = peer 1 and b = peer 2 and c = peer 3 in
  let sa = seal_for a and sb = seal_for b and sc = seal_for c in
  let plain = "a secret share" in
  let sealed = Seal.seal sa ~peer:b plain in
  Alcotest.(check bool)
    "ciphertext differs from plaintext" true
    (not (String.equal sealed plain));
  Alcotest.(check int)
    "overhead is nonce plus tag"
    (String.length plain + Seal.overhead)
    (String.length sealed);
  (match Seal.unseal sb ~peer:a sealed with
  | Ok p -> Alcotest.(check string) "the recipient opens it" plain p
  | Error e -> Alcotest.failf "unseal failed: %s" (Mpc.Error.to_string e));
  Alcotest.(check bool)
    "a third party cannot open it" true
    (Result.is_error (Seal.unseal sc ~peer:a sealed));
  (* Anti-reflection: the sender cannot open its own outbound payload, so a captured
     message cannot be bounced back and accepted as if it came from the far end. *)
  Alcotest.(check bool)
    "the sender cannot open its own outbound payload" true
    (Result.is_error (Seal.unseal sa ~peer:b sealed));
  (* Two seals of the same plaintext must differ: the nonce is drawn fresh. *)
  Alcotest.(check bool)
    "nonces are not reused" true
    (not (String.equal sealed (Seal.seal sa ~peer:b plain)));
  (* Flipping any byte must fail authentication. *)
  let flip i =
    String.mapi
      (fun j ch -> if j = i then Char.chr (Char.code ch lxor 1) else ch)
      sealed
  in
  for i = 0 to String.length sealed - 1 do
    Alcotest.(check bool)
      (Printf.sprintf "corrupting byte %d is detected" i)
      true
      (Result.is_error (Seal.unseal sb ~peer:a (flip i)))
  done;
  Lwt.return_unit

let t_private_payload_needs_the_seal _ () =
  (* The driver's wire record is where the seal is bound. Without one, a DKG round-2
     message cannot be encoded -- which is the point: the alternative is a secret share
     on the wire. *)
  let m =
    Msg.make
      ~session:(Result.get_ok (Sess.session_id (String.make 32 '\001')))
      ~round:1 ~src:(peer 1) ~dst:(peer 2)
      (Msg.Dkg_share { value = Sc.one })
  in
  Alcotest.(check bool)
    "unsealed encoding is refused" true
    (Msg.encode m = Error `Unsealed_private_payload);
  Lwt.return_unit

let t_address_parsing _ () =
  let ok s expected =
    match Mpc_unix.parse_address s with
    | Ok a ->
        Alcotest.(check string)
          s expected
          (Format.asprintf "%a" Mpc_unix.pp_address a)
    | Error (`Msg m) -> Alcotest.failf "%s: %s" s m
  in
  ok "127.0.0.1:9000" "127.0.0.1:9000";
  ok "unix:/tmp/x.sock" "unix:/tmp/x.sock";
  ok ":9000" "0.0.0.0:9000";
  List.iter
    (fun s ->
      Alcotest.(check bool)
        (Printf.sprintf "%S is rejected" s)
        true
        (Result.is_error (Mpc_unix.parse_address s)))
    [ "nonsense"; "host:0"; "host:65536"; "host:notaport" ];
  Lwt.return_unit

let () =
  Mirage_crypto_rng_unix.use_default ();
  Lwt_main.run
    (Alcotest_lwt.run "mpc-unix"
       [
         ( "transport",
           [
             Alcotest_lwt.test_case "address parsing" `Quick t_address_parsing;
             Alcotest_lwt.test_case "seal round trip" `Quick t_seal_roundtrip;
             Alcotest_lwt.test_case "private payloads need the seal" `Quick
               t_private_payload_needs_the_seal;
           ] );
         ( "end-to-end",
           [
             Alcotest_lwt.test_case "DKG then sign over sockets" `Slow
               t_dkg_and_sign;
           ] );
       ])
