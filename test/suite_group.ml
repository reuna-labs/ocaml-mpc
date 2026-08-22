(** Scalar-field and group laws for the Ed25519 ciphersuite.

    These are the tests that validate the derived primitives: [scalar_mul] built
    out of [verify_double_base], [invert] built out of repeated [scalar_muladd],
    and the canonicity and prime-order-subgroup checks that mirage-crypto's
    decoder does not perform. If any of them regresses, nothing above this layer
    can be trusted. *)

open Testutil.Ed25519

(* ---- scalar field ---- *)

let t_scalar_ring () =
  let xs = some_scalars 8 "ring" in
  List.iter
    (fun a ->
      Alcotest.check sc "a + 0 = a" a (Sc.add a Sc.zero);
      Alcotest.check sc "a * 1 = a" a (Sc.mul a Sc.one);
      Alcotest.check sc "a - a = 0" Sc.zero (Sc.sub a a);
      Alcotest.check sc "a + (-a) = 0" Sc.zero (Sc.add a (Sc.neg a));
      Alcotest.check sc "-(-a) = a" a (Sc.neg (Sc.neg a)))
    xs;
  List.iter2
    (fun a b ->
      Alcotest.check sc "commutative +" (Sc.add a b) (Sc.add b a);
      Alcotest.check sc "commutative *" (Sc.mul a b) (Sc.mul b a);
      Alcotest.check sc "muladd" (Sc.add (Sc.mul a b) a) (Sc.muladd a b a);
      Alcotest.check sc "a - b = a + (-b)" (Sc.sub a b) (Sc.add a (Sc.neg b)))
    xs (List.rev xs)

let t_scalar_invert () =
  let xs = some_scalars 6 "invert" in
  List.iter
    (fun a ->
      let ai = Result.get_ok (Sc.invert a) in
      Alcotest.check sc "a * a^-1 = 1" Sc.one (Sc.mul a ai))
    xs;
  Alcotest.(check bool)
    "invert 0 fails" true
    (Result.is_error (Sc.invert Sc.zero))

let t_scalar_invert_batch () =
  let xs = Array.of_list (some_scalars 5 "batch") in
  let inv = Result.get_ok (Sc.invert_batch xs) in
  Array.iteri
    (fun i a ->
      Alcotest.check sc "batch agrees with single"
        (Result.get_ok (Sc.invert a))
        inv.(i))
    xs;
  Alcotest.(check bool) "empty" true (Sc.invert_batch [||] = Ok [||]);
  Alcotest.(check bool)
    "zero in batch fails" true
    (Result.is_error (Sc.invert_batch [| Sc.one; Sc.zero |]))

let t_scalar_codec () =
  List.iter
    (fun a ->
      Alcotest.check sc "round trip" a
        (Result.get_ok (Sc.deserialize (Sc.serialize a))))
    (some_scalars 4 "codec");
  Alcotest.(check bool)
    "short rejected" true
    (Sc.deserialize (String.make 31 '\000') = Error `Invalid_length);
  (* L itself, little-endian: the smallest non-reduced value. *)
  let l =
    Ohex.decode
      "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
  in
  Alcotest.(check bool)
    "L rejected" true
    (Sc.deserialize l = Error `Invalid_range);
  Alcotest.(check bool)
    "L-1 accepted" true
    (Result.is_ok
       (Sc.deserialize
          (Ohex.decode
             "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")))

let t_scalar_of_int () =
  Alcotest.(check bool) "0 rejected" true (Sc.of_int 0 = Error `Invalid_range);
  Alcotest.(check bool)
    "65536 rejected" true
    (Sc.of_int 65536 = Error `Invalid_range);
  Alcotest.check sc "1" Sc.one (Result.get_ok (Sc.of_int 1));
  let two = Result.get_ok (Sc.of_int 2) in
  Alcotest.check sc "2 = 1+1" (Sc.add Sc.one Sc.one) two;
  let n = 65535 in
  let by_add =
    List.fold_left
      (fun a _ -> Sc.add a Sc.one)
      Sc.zero
      (List.init n (fun _ -> ()))
  in
  Alcotest.check sc "65535 by repeated addition" by_add
    (Result.get_ok (Sc.of_int n))

(* ---- group ---- *)

let t_group_laws () =
  let xs = some_scalars 5 "group" in
  Alcotest.check el "G = 1*G" El.generator (El.scalar_mul_base Sc.one);
  Alcotest.check el "0*G = identity" El.identity (El.scalar_mul_base Sc.zero);
  Alcotest.(check bool) "identity is identity" true (El.is_identity El.identity);
  List.iter
    (fun a ->
      let p = El.scalar_mul_base a in
      Alcotest.check el "scalar_mul agrees with scalar_mul_base" p
        (El.scalar_mul a El.generator);
      Alcotest.check el "p + identity = p" p (El.add p El.identity);
      Alcotest.check el "p - p = identity" El.identity (El.sub p p);
      Alcotest.check el "-(-p) = p" p (El.neg (El.neg p)))
    xs;
  List.iter2
    (fun a b ->
      let pa = El.scalar_mul_base a and pb = El.scalar_mul_base b in
      Alcotest.check el "commutative" (El.add pa pb) (El.add pb pa);
      Alcotest.check el "homomorphism: (a+b)G = aG + bG"
        (El.scalar_mul_base (Sc.add a b))
        (El.add pa pb);
      Alcotest.check el "(a*b)G = a*(bG)"
        (El.scalar_mul_base (Sc.mul a b))
        (El.scalar_mul a pb))
    xs (List.rev xs)

let t_group_small_mults () =
  (* scalar_mul against repeated addition, for small public scalars. *)
  let g = El.generator in
  let acc = ref El.identity in
  for k = 0 to 16 do
    let s = if k = 0 then Sc.zero else Result.get_ok (Sc.of_int k) in
    Alcotest.check el
      (Printf.sprintf "%d*G by repeated add" k)
      !acc (El.scalar_mul s g);
    acc := El.add !acc g
  done

let t_element_codec () =
  List.iter
    (fun a ->
      let p = El.scalar_mul_base a in
      Alcotest.check el "round trip" p
        (Result.get_ok (El.deserialize (El.serialize p))))
    (some_scalars 4 "ecodec");
  Alcotest.(check bool)
    "short rejected" true
    (El.deserialize (String.make 31 '\000') = Error `Invalid_length);
  Alcotest.(check bool)
    "identity rejected" true
    (El.deserialize (El.serialize El.identity) = Error `At_infinity);
  (* Non-canonical: y = p (= 0 mod p) with the low bit pattern of p itself. *)
  let non_canonical =
    Ohex.decode
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
  in
  Alcotest.(check bool)
    "non-canonical y rejected" true
    (El.deserialize non_canonical = Error `Invalid_format)

let t_torsion () =
  (* The eight small-order points of edwards25519, RFC 8032 encodings. None lies in
     the prime-order subgroup; DeserializeElement must reject every one. *)
  let small =
    [
      "0100000000000000000000000000000000000000000000000000000000000000";
      "0000000000000000000000000000000000000000000000000000000000000000";
      "0000000000000000000000000000000000000000000000000000000000000080";
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05";
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85";
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa";
    ]
  in
  List.iteri
    (fun i h ->
      let r = El.deserialize (Ohex.decode h) in
      Alcotest.(check bool)
        (Printf.sprintf "small-order point %d rejected" i)
        true (Result.is_error r))
    small

(* ---- wipeable accumulator ---- *)

module Acc = Sc.Acc

let t_acc_matches_scalar_ops () =
  let xs = some_scalars 6 "acc" in
  List.iter
    (fun a ->
      Alcotest.check sc "of_scalar then reveal is the identity" a
        (Acc.reveal (Acc.of_scalar a)))
    xs;
  List.iter2
    (fun a b ->
      let d = Acc.create () in
      let ka = Acc.of_scalar a and kb = Acc.of_scalar b in
      Acc.muladd ~dst:d ~a:ka ~b:kb ~c:(Acc.of_scalar Sc.zero);
      Alcotest.check sc "muladd with c = 0 is multiplication" (Sc.mul a b)
        (Acc.reveal d);
      Acc.muladd ~dst:d ~a:ka ~b:kb ~c:(Acc.of_scalar a);
      Alcotest.check sc "muladd" (Sc.add (Sc.mul a b) a) (Acc.reveal d);
      let e = Acc.of_scalar a in
      Acc.add ~dst:e (Acc.of_scalar b);
      Alcotest.check sc "add" (Sc.add a b) (Acc.reveal e))
    xs (List.rev xs)

let t_acc_aliasing () =
  (* Every operand may be the same buffer as the destination. If the C stub did not
     load its inputs before storing, this would silently produce wrong arithmetic --
     and wrong signatures -- rather than crash. *)
  let a = List.hd (some_scalars 1 "alias") in
  let b = List.hd (some_scalars 1 "alias2") in
  let d = Acc.of_scalar a in
  Acc.muladd ~dst:d ~a:d ~b:(Acc.of_scalar b) ~c:(Acc.of_scalar Sc.zero);
  Alcotest.check sc "dst aliases a" (Sc.mul a b) (Acc.reveal d);
  let e = Acc.of_scalar a in
  Acc.muladd ~dst:e ~a:e ~b:e ~c:e;
  Alcotest.check sc "dst aliases every operand"
    (Sc.add (Sc.mul a a) a)
    (Acc.reveal e);
  let f = Acc.of_scalar a in
  Acc.add ~dst:f f;
  Alcotest.check sc "add aliasing itself doubles" (Sc.add a a) (Acc.reveal f)

let t_acc_wipe () =
  let a = List.hd (some_scalars 1 "accwipe") in
  let d = Acc.of_scalar a in
  Alcotest.(check bool) "live before wiping" false (Acc.wiped d);
  Acc.wipe d;
  Alcotest.(check bool) "wiped" true (Acc.wiped d);
  Alcotest.check sc "and reads as zero" Sc.zero (Acc.reveal d);
  Acc.wipe d;
  Alcotest.(check bool) "wiping twice is fine" true (Acc.wiped d);
  (* A freshly created accumulator is zero, and therefore reports as wiped: the
     predicate is about content, not about a flag. *)
  Alcotest.(check bool)
    "a fresh accumulator is zero" true
    (Acc.wiped (Acc.create ()))

let t_acc_horner () =
  (* The shape Shamir.eval uses: evaluate a polynomial by repeated muladd into one
     buffer, and check it against the same computation done with plain scalars. *)
  let coeffs = some_scalars 5 "horner" in
  let x = List.hd (some_scalars 1 "hornerx") in
  let expected =
    List.fold_left (fun acc c -> Sc.muladd acc x c) Sc.zero (List.rev coeffs)
  in
  let d = Acc.create () in
  let kx = Acc.of_scalar x in
  List.iter
    (fun c -> Acc.muladd ~dst:d ~a:d ~b:kx ~c:(Acc.of_scalar c))
    (List.rev coeffs);
  Alcotest.check sc "Horner in an accumulator agrees with plain scalars"
    expected (Acc.reveal d)

let suites =
  [
    ( "scalar",
      [
        Alcotest.test_case "ring laws" `Quick t_scalar_ring;
        Alcotest.test_case "inversion" `Quick t_scalar_invert;
        Alcotest.test_case "batch inversion" `Quick t_scalar_invert_batch;
        Alcotest.test_case "serialization" `Quick t_scalar_codec;
        Alcotest.test_case "of_int" `Quick t_scalar_of_int;
      ] );
    ( "group",
      [
        Alcotest.test_case "laws" `Quick t_group_laws;
        Alcotest.test_case "small multiples" `Quick t_group_small_mults;
        Alcotest.test_case "serialization" `Quick t_element_codec;
        Alcotest.test_case "torsion rejection" `Quick t_torsion;
      ] );
    ( "accumulator",
      [
        Alcotest.test_case "agrees with scalar operations" `Quick
          t_acc_matches_scalar_ops;
        Alcotest.test_case "aliasing is safe" `Quick t_acc_aliasing;
        Alcotest.test_case "wipe" `Quick t_acc_wipe;
        Alcotest.test_case "Horner" `Quick t_acc_horner;
      ] );
  ]
