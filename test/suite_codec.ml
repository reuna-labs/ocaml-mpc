(** The wire codec and the message format.

    Two things are being defended here. First, that a hostile peer cannot make a
    unikernel allocate: every count is checked against the bytes remaining
    before anything is built. Second, that a private payload cannot leave the
    process unsealed — the DKG round-2 share is a secret, and an observer who
    collects [t] of them holds the key. *)

open Testutil.Ed25519
module W = Mpc.Codec.W
module R = Mpc.Codec.R
module M = Mpc_frost.Msg.Make (Mpc_ed25519.Suite)
module Sess = Mpc.Session

let peer n = Result.get_ok (Sess.peer n)
let session = Result.get_ok (Sess.session_id (String.make 32 '\042'))

(* --- primitives --- *)

let t_int_roundtrip () =
  List.iter
    (fun v ->
      let s = W.to_string (fun w x -> W.u16 w x) v in
      Alcotest.(check int) "u16" 2 (String.length s);
      Alcotest.(check int) "u16 round trip" v (Result.get_ok (R.run R.u16 s)))
    [ 0; 1; 255; 256; 0xffff ];
  List.iter
    (fun v ->
      let s = W.to_string (fun w x -> W.u32 w x) v in
      Alcotest.(check int) "u32" 4 (String.length s);
      Alcotest.(check bool)
        "u32 round trip" true
        (Result.get_ok (R.run R.u32 s) = v))
    [ 0l; 1l; 0x7fffffffl; -1l ];
  (* Big-endian, and only big-endian: 0x0102 must serialise high byte first. *)
  Alcotest.(check string)
    "big-endian" "0102"
    (Ohex.encode (W.to_string W.u16 0x0102))

let t_eof_and_trailing () =
  Alcotest.(check bool)
    "short input is Eof" true
    (match R.run R.u32 "ab" with Error (`Eof 2) -> true | _ -> false);
  Alcotest.(check bool)
    "unconsumed input is Trailing" true
    (match R.run R.u16 "abcd" with Error (`Trailing 2) -> true | _ -> false);
  Alcotest.(check bool)
    "exact:false permits trailing" true
    (Result.is_ok (R.run ~exact:false R.u16 "abcd"))

let t_hostile_counts () =
  (* A count larger than the bytes that remain cannot be honest: every element occupies
     at least one byte. Rejecting before allocating is what stops a hostile length from
     exhausting a unikernel's heap. *)
  let claim_65535_elements = "\xff\xff" in
  Alcotest.(check bool)
    "count16 beyond remaining is rejected" true
    (match R.run R.count16 claim_65535_elements with
    | Error (`Eof _) -> true
    | _ -> false);
  Alcotest.(check bool)
    "vector16 with a hostile count is rejected" true
    (Result.is_error (R.run (fun r -> R.vector16 r R.u8) claim_65535_elements));
  (* Same for a 32-bit length. *)
  Alcotest.(check bool)
    "str32 beyond remaining is rejected" true
    (Result.is_error (R.run R.str32 "\x7f\xff\xff\xff"));
  Alcotest.(check bool)
    "a negative 32-bit length is rejected" true
    (Result.is_error (R.run R.str32 "\xff\xff\xff\xffdata"))

let t_strings () =
  List.iter
    (fun s ->
      Alcotest.(check string)
        "str16 round trip" s
        (Result.get_ok (R.run R.str16 (W.to_string W.str16 s)));
      Alcotest.(check string)
        "str32 round trip" s
        (Result.get_ok (R.run R.str32 (W.to_string W.str32 s))))
    [ ""; "a"; String.make 1000 'x' ]

let t_fixed_rejects_wrong_length () =
  (* A writer cannot fail on well-typed input, so a length mismatch here is a bug in the
     caller rather than malformed input, and is reported as such. *)
  Alcotest.check_raises "fixed with the wrong length"
    (Invalid_argument "Mpc.Codec.W.fixed: expected 4 bytes, got 3") (fun () ->
      ignore (W.to_string (fun w s -> W.fixed w ~len:4 s) "abc"))

(* --- messages --- *)

let a_commitment () =
  let r = rand_of_seed "codec" in
  let s = Result.get_ok (Sc.random r) in
  (El.scalar_mul_base s, El.scalar_mul_base (Sc.add s Sc.one))

let t_message_roundtrip () =
  let h, b = a_commitment () in
  let payloads =
    [
      M.Sign_commit { hiding = h; binding = b };
      M.Sign_share { z = Result.get_ok (Sc.random (rand_of_seed "z")) };
      M.Sign_package
        { commitments = [ (id 1, (h, b)); (id 3, (h, b)) ]; msg = "hello" };
      M.Dkg_commit { commitment = [| h; b |]; pok_r = h; pok_mu = Sc.one };
      M.Abort
        {
          Sess.code = `Bad_share;
          culprits = [ peer 2; peer 5 ];
          round = 1;
          detail = "why";
        };
    ]
  in
  List.iter
    (fun payload ->
      let m = M.make ~session ~round:1 ~src:(peer 7) ~dst:(peer 9) payload in
      let bytes = Result.get_ok (M.encode m) in
      let m' = Result.get_ok (M.decode bytes) in
      Alcotest.(check int) "src" 7 (Sess.peer_to_int m'.M.src);
      Alcotest.(check bool) "dst" true (m'.M.dst = Some (peer 9));
      Alcotest.(check int) "round" 1 m'.M.round;
      Alcotest.(check string)
        "session"
        (m.M.session :> string)
        (m'.M.session :> string);
      Alcotest.(check string)
        "payload is identical"
        (Ohex.encode (M.encode_payload payload))
        (Ohex.encode (M.encode_payload m'.M.payload)))
    payloads

let t_broadcast_has_no_dst () =
  let h, b = a_commitment () in
  let m =
    M.make ~session ~round:0 ~src:(peer 1)
      (M.Sign_commit { hiding = h; binding = b })
  in
  let m' = Result.get_ok (M.decode (Result.get_ok (M.encode m))) in
  Alcotest.(check bool)
    "broadcast decodes with no destination" true (m'.M.dst = None)

let t_private_payload_needs_a_seal () =
  let payload = M.Dkg_share { value = Sc.one } in
  Alcotest.(check bool) "a DKG share is private" true (M.is_private payload);
  let m = M.make ~session ~round:1 ~src:(peer 1) ~dst:(peer 2) payload in
  (* This is the whole point: forgetting to encrypt DKG shares is a total key
     compromise, so it is an error at the call site, not a sentence in a README. *)
  Alcotest.(check bool)
    "encoding without a seal is refused" true
    (M.encode m = Error `Unsealed_private_payload);
  Alcotest.(check bool)
    "a private payload with no recipient is refused" true
    (M.encode
       ~seal:(fun ~peer:_ s -> s)
       (M.make ~session ~round:1 ~src:(peer 1) payload)
    = Error `Unsealed_private_payload);
  (* The counterpart differs by direction: [encode] seals to the destination, [decode]
     unseals from the source. Both must name the same pair, which this stub checks by
     labelling the ciphertext with the peer it was handed. *)
  let seal ~peer s = string_of_int (Sess.peer_to_int peer) ^ "|" ^ s in
  let unseal ~peer s =
    let want = string_of_int (Sess.peer_to_int peer) ^ "|" in
    let n = String.length want in
    if String.length s >= n && String.sub s 0 n = want then
      Ok (String.sub s n (String.length s - n))
    else Error `Invalid_format
  in
  let bytes = Result.get_ok (M.encode ~seal m) in
  (* Sealed to peer 2 (the destination); the recipient unseals naming peer 1 (the
     source), so the stub's label must be the one the sender used. It is not -- which
     is exactly right: the two ends name the *pair*, and this stub, keyed on a single
     peer, cannot. A real seal keys on the ordered pair; see Mpc_lwt.Sealed. *)
  Alcotest.(check bool)
    "a one-sided key does not open the other direction" true
    (Result.is_error (M.decode ~unseal bytes));
  (* Model the pair properly: label with both endpoints in the order the sender used. *)
  let src = peer 1 and dst = peer 2 in
  let tag a b =
    Printf.sprintf "%d>%d|" (Sess.peer_to_int a) (Sess.peer_to_int b)
  in
  let seal2 ~peer s = tag src peer ^ s in
  let unseal2 ~peer s =
    let want = tag peer dst in
    let n = String.length want in
    if String.length s >= n && String.sub s 0 n = want then
      Ok (String.sub s n (String.length s - n))
    else Error `Invalid_format
  in
  let bytes2 = Result.get_ok (M.encode ~seal:seal2 m) in
  let m' = Result.get_ok (M.decode ~unseal:unseal2 bytes2) in
  Alcotest.(check string)
    "sealed payload round trips"
    (Ohex.encode (M.encode_payload payload))
    (Ohex.encode (M.encode_payload m'.M.payload));
  Alcotest.(check bool)
    "decoding a sealed payload without unseal is refused" true
    (M.decode bytes2 = Error `Unsealed_private_payload)

let t_rejects_foreign_and_malformed () =
  let h, b = a_commitment () in
  let m =
    M.make ~session ~round:0 ~src:(peer 1)
      (M.Sign_commit { hiding = h; binding = b })
  in
  let bytes = Result.get_ok (M.encode m) in
  let flip i c s = String.mapi (fun j x -> if j = i then c else x) s in
  Alcotest.(check bool)
    "a foreign version is rejected" true
    (Result.is_error (M.decode (flip 0 '\002' bytes)));
  Alcotest.(check bool)
    "a foreign protocol is rejected" true
    (Result.is_error (M.decode (flip 1 '\099' bytes)));
  Alcotest.(check bool)
    "a foreign ciphersuite is rejected" true
    (Result.is_error (M.decode (flip 2 '\099' bytes)));
  Alcotest.(check bool)
    "an unknown payload kind is rejected" true
    (Result.is_error (M.decode (flip 3 '\099' bytes)));
  Alcotest.(check bool)
    "src 0 is not a valid peer" true
    (Result.is_error (M.decode (flip 36 '\000' (flip 37 '\000' bytes))));
  (* Truncation at every length must be an error, never an exception. *)
  for i = 0 to String.length bytes - 1 do
    match M.decode (String.sub bytes 0 i) with
    | Error _ -> ()
    | Ok _ -> Alcotest.failf "a message truncated to %d bytes was accepted" i
  done

let t_header_peek () =
  let h, b = a_commitment () in
  let m =
    M.make ~session ~round:1 ~src:(peer 4) ~dst:(peer 6)
      (M.Sign_commit { hiding = h; binding = b })
  in
  let bytes = Result.get_ok (M.encode m) in
  match M.decode_header bytes with
  | Error _ -> Alcotest.fail "header should decode"
  | Ok (v, suite, sid, round, src, dst) ->
      Alcotest.(check int) "version" M.version v;
      Alcotest.(check int) "suite tag" Mpc_ed25519.Suite.suite_tag suite;
      Alcotest.(check string) "session" (session :> string) (sid :> string);
      Alcotest.(check int) "round" 1 round;
      Alcotest.(check int) "src" 4 (Sess.peer_to_int src);
      Alcotest.(check bool) "dst" true (dst = Some (peer 6))

(* --- session identifiers --- *)

let t_session_id () =
  let d =
    Sess.derive_session_id ~domain:"d" ~group_public_key:"pk"
      ~participants:[ peer 1; peer 2 ]
      ~context:"c" ~nonce:(String.make 32 '\000')
  in
  Alcotest.(check int) "32 bytes" 32 (String.length (d :> string));
  (* Order of the participant list must not matter; its membership must. *)
  let d' =
    Sess.derive_session_id ~domain:"d" ~group_public_key:"pk"
      ~participants:[ peer 2; peer 1 ]
      ~context:"c" ~nonce:(String.make 32 '\000')
  in
  Alcotest.(check string)
    "participant order is irrelevant"
    (d :> string)
    (d' :> string);
  let d'' =
    Sess.derive_session_id ~domain:"d" ~group_public_key:"pk"
      ~participants:[ peer 1; peer 3 ]
      ~context:"c" ~nonce:(String.make 32 '\000')
  in
  Alcotest.(check bool)
    "a different signer set differs" true
    ((d :> string) <> (d'' :> string));
  (* Fields are length-prefixed, so no two distinct inputs can collide by concatenation. *)
  let a =
    Sess.derive_session_id ~domain:"ab" ~group_public_key:"c" ~participants:[]
      ~context:"" ~nonce:""
  in
  let b =
    Sess.derive_session_id ~domain:"a" ~group_public_key:"bc" ~participants:[]
      ~context:"" ~nonce:""
  in
  Alcotest.(check bool)
    "field boundaries are unambiguous" true
    ((a :> string) <> (b :> string));
  Alcotest.(check bool)
    "a fresh nonce gives a fresh identifier" true
    ((d :> string)
    <> (Sess.derive_session_id ~domain:"d" ~group_public_key:"pk"
          ~participants:[ peer 1; peer 2 ]
          ~context:"c" ~nonce:(String.make 32 '\001')
         :> string))

let t_peer_range () =
  Alcotest.(check bool) "0 is not a peer" true (Result.is_error (Sess.peer 0));
  Alcotest.(check bool)
    "65536 is not a peer" true
    (Result.is_error (Sess.peer 65536));
  Alcotest.(check bool) "1 is" true (Result.is_ok (Sess.peer 1));
  Alcotest.(check bool) "65535 is" true (Result.is_ok (Sess.peer 65535));
  Alcotest.(check bool)
    "a 31-byte session id is rejected" true
    (Result.is_error (Sess.session_id (String.make 31 'x')))

let suites =
  [
    ( "codec",
      [
        Alcotest.test_case "integer round trips" `Quick t_int_roundtrip;
        Alcotest.test_case "eof and trailing" `Quick t_eof_and_trailing;
        Alcotest.test_case "hostile counts" `Quick t_hostile_counts;
        Alcotest.test_case "strings" `Quick t_strings;
        Alcotest.test_case "fixed length" `Quick t_fixed_rejects_wrong_length;
      ] );
    ( "wire",
      [
        Alcotest.test_case "message round trip" `Quick t_message_roundtrip;
        Alcotest.test_case "broadcast" `Quick t_broadcast_has_no_dst;
        Alcotest.test_case "private payloads need a seal" `Quick
          t_private_payload_needs_a_seal;
        Alcotest.test_case "foreign and malformed input" `Quick
          t_rejects_foreign_and_malformed;
        Alcotest.test_case "header peek" `Quick t_header_peek;
      ] );
    ( "session",
      [
        Alcotest.test_case "identifier derivation" `Quick t_session_id;
        Alcotest.test_case "peer range" `Quick t_peer_range;
      ] );
  ]
