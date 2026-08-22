(** RFC 9380 [expand_message_xmd] known-answer tests.

    The secp256k1 ciphersuite maps bytes to scalars through [hash_to_field],
    which is built on this expander. Testing it separately means a later failure
    in a FROST binding factor localises to the protocol rather than being
    ambiguous between the two. The long-DST cases matter in particular: a DST
    over 255 bytes has to be hashed down first, and an implementation that skips
    that produces plausible-looking output that agrees with nobody. *)

let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))

let expand =
  Mpc.Xmd.expand_message_xmd ~hash:sha256 ~block_size:64 ~digest_size:32

let load () =
  let file = "vectors/rfc9380-expand-message-xmd-sha256.json" in
  try Yojson.Safe.from_file file
  with _ -> Alcotest.failf "cannot read %s" file

let mem k j =
  match j with
  | `Assoc l -> List.assoc k l
  | _ -> Alcotest.failf "not an object"

let str j = match j with `String s -> s | _ -> Alcotest.failf "not a string"
let int_ j = match j with `Int i -> i | _ -> Alcotest.failf "not an int"

let run_block name =
  let j = mem name (load ()) in
  let dst = str (mem "dst" j) in
  let cases =
    match mem "cases" j with `List l -> l | _ -> Alcotest.failf "cases"
  in
  Alcotest.(check bool) "the block has cases" true (cases <> []);
  List.iter
    (fun c ->
      let msg = str (mem "msg" c) in
      let len = int_ (mem "len" c) in
      let want = str (mem "uniform_bytes" c) in
      match expand ~dst ~msg ~len with
      | Error _ ->
          Alcotest.failf "expand_message_xmd rejected a valid case (len %d)" len
      | Ok got ->
          Alcotest.(check string)
            (Printf.sprintf "%s msg=%S len=%d" name msg len)
            want (Ohex.encode got))
    cases

let t_short_dst () = run_block "k1"
let t_long_dst () = run_block "k2"

let t_bounds () =
  (* len is carried in a one-byte counter's worth of blocks; beyond that the counter
     would wrap and the output would silently repeat. *)
  Alcotest.(check bool)
    "zero length is rejected" true
    (Result.is_error (expand ~dst:"x" ~msg:"" ~len:0));
  Alcotest.(check bool)
    "255 * digest_size is accepted" true
    (Result.is_ok (expand ~dst:"x" ~msg:"" ~len:(255 * 32)));
  Alcotest.(check bool)
    "one byte more is rejected" true
    (Result.is_error (expand ~dst:"x" ~msg:"" ~len:((255 * 32) + 1)))

let suites =
  [
    ( "rfc9380-xmd",
      [
        Alcotest.test_case "short DST" `Quick t_short_dst;
        Alcotest.test_case "long DST" `Quick t_long_dst;
        Alcotest.test_case "length bounds" `Quick t_bounds;
      ] );
  ]
