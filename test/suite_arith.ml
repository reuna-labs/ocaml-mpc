(** Scalar-field and group laws, for any ciphersuite.

    These are the checks that must hold on every curve, so they are a functor
    and run against each. Curve-specific ones stay with their suite: rejecting
    the eight small-order points is meaningful on edwards25519, whose cofactor
    is 8, and meaningless on secp256k1, whose cofactor is 1. *)

module Make
    (C : Mpc.Group.CIPHERSUITE)
    (N : sig
      val name : string
    end) =
struct
  include Testutil.Make (C)
  module Acc = Sc.Acc

  let t_scalar_ring () =
    let xs = some_scalars 8 (N.name ^ "ring") in
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
    List.iter
      (fun a ->
        let ai = Result.get_ok (Sc.invert a) in
        Alcotest.check sc "a * a^-1 = 1" Sc.one (Sc.mul a ai))
      (some_scalars 6 (N.name ^ "inv"));
    Alcotest.(check bool)
      "invert 0 fails" true
      (Result.is_error (Sc.invert Sc.zero))

  let t_scalar_invert_batch () =
    let xs = Array.of_list (some_scalars 5 (N.name ^ "batch")) in
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
      (some_scalars 4 (N.name ^ "codec"));
    Alcotest.(check int)
      "serialized length" C.ns
      (String.length (Sc.serialize Sc.one));
    Alcotest.(check bool)
      "a short encoding is rejected" true
      (Sc.deserialize (String.make (C.ns - 1) '\000') = Error `Invalid_length)

  let t_of_int () =
    Alcotest.(check bool) "0 rejected" true (Sc.of_int 0 = Error `Invalid_range);
    Alcotest.(check bool)
      "65536 rejected" true
      (Sc.of_int 65536 = Error `Invalid_range);
    Alcotest.check sc "1" Sc.one (id 1);
    Alcotest.check sc "2 = 1 + 1" (Sc.add Sc.one Sc.one) (id 2);
    (* Identifiers must order numerically whatever the serialisation endianness: the
       commitment list is sorted by identifier and both ends must agree on the order. *)
    Alcotest.(check bool)
      "compare orders numerically" true
      (Sc.compare (id 1) (id 2) < 0
      && Sc.compare (id 2) (id 1) > 0
      && Sc.compare (id 7) (id 7) = 0
      && Sc.compare (id 255) (id 256) < 0)

  let t_group_laws () =
    let xs = some_scalars 5 (N.name ^ "group") in
    Alcotest.check el "G = 1*G" El.generator (El.scalar_mul_base Sc.one);
    Alcotest.check el "0*G = identity" El.identity (El.scalar_mul_base Sc.zero);
    Alcotest.(check bool)
      "identity is identity" true
      (El.is_identity El.identity);
    Alcotest.(check int)
      "serialized length" C.ne
      (String.length (El.serialize El.generator));
    List.iter
      (fun a ->
        let p = El.scalar_mul_base a in
        Alcotest.check el "scalar_mul agrees with scalar_mul_base" p
          (El.scalar_mul a El.generator);
        Alcotest.check el "p + identity = p" p (El.add p El.identity);
        Alcotest.check el "p - p = identity" El.identity (El.sub p p);
        Alcotest.check el "-(-p) = p" p (El.neg (El.neg p));
        Alcotest.check el "p + p = 2p" (El.add p p) (El.scalar_mul (id 2) p))
      xs;
    List.iter2
      (fun a b ->
        let pa = El.scalar_mul_base a and pb = El.scalar_mul_base b in
        Alcotest.check el "commutative" (El.add pa pb) (El.add pb pa);
        Alcotest.check el "(a+b)G = aG + bG"
          (El.scalar_mul_base (Sc.add a b))
          (El.add pa pb);
        Alcotest.check el "(a*b)G = a*(bG)"
          (El.scalar_mul_base (Sc.mul a b))
          (El.scalar_mul a pb))
      xs (List.rev xs)

  let t_small_multiples () =
    (* scalar_mul against repeated addition. If the ladder disagrees with the group law
       for small scalars it will disagree for large ones, and only this catches it. *)
    let g = El.generator in
    let acc = ref El.identity in
    for k = 0 to 16 do
      let s = if k = 0 then Sc.zero else id k in
      Alcotest.check el
        (Printf.sprintf "%d*G by repeated addition" k)
        !acc (El.scalar_mul s g);
      acc := El.add !acc g
    done

  let t_element_codec () =
    List.iter
      (fun a ->
        let p = El.scalar_mul_base a in
        Alcotest.check el "round trip" p
          (Result.get_ok (El.deserialize (El.serialize p))))
      (some_scalars 4 (N.name ^ "ecodec"));
    Alcotest.(check bool)
      "a short encoding is rejected" true
      (El.deserialize (String.make (C.ne - 1) '\000') = Error `Invalid_length);
    Alcotest.(check bool)
      "the identity is rejected" true
      (El.deserialize (El.serialize El.identity) = Error `At_infinity)

  let t_accumulator () =
    let xs = some_scalars 6 (N.name ^ "acc") in
    List.iter
      (fun a ->
        Alcotest.check sc "of_scalar then reveal" a
          (Acc.reveal (Acc.of_scalar a)))
      xs;
    List.iter2
      (fun a b ->
        let d = Acc.create () in
        let ka = Acc.of_scalar a and kb = Acc.of_scalar b in
        Acc.muladd ~dst:d ~a:ka ~b:kb ~c:(Acc.create ());
        Alcotest.check sc "muladd with c = 0 is multiplication" (Sc.mul a b)
          (Acc.reveal d);
        Acc.muladd ~dst:d ~a:ka ~b:kb ~c:ka;
        Alcotest.check sc "muladd" (Sc.add (Sc.mul a b) a) (Acc.reveal d);
        let e = Acc.of_scalar a in
        Acc.add ~dst:e (Acc.of_scalar b);
        Alcotest.check sc "add" (Sc.add a b) (Acc.reveal e))
      xs (List.rev xs);
    (* Every operand may alias the destination. If the underlying primitive stored
       before loading, this would corrupt arithmetic silently rather than crash. *)
    let a = List.hd xs and b = List.nth xs 1 in
    let d = Acc.of_scalar a in
    Acc.muladd ~dst:d ~a:d ~b:(Acc.of_scalar b) ~c:(Acc.create ());
    Alcotest.check sc "dst aliases a" (Sc.mul a b) (Acc.reveal d);
    let e = Acc.of_scalar a in
    Acc.muladd ~dst:e ~a:e ~b:e ~c:e;
    Alcotest.check sc "dst aliases every operand"
      (Sc.add (Sc.mul a a) a)
      (Acc.reveal e);
    (* Wiping *)
    let f = Acc.of_scalar a in
    Alcotest.(check bool) "live before wiping" false (Acc.wiped f);
    Acc.wipe f;
    Alcotest.(check bool) "wiped" true (Acc.wiped f);
    Alcotest.check sc "and reads as zero" Sc.zero (Acc.reveal f)

  let suites =
    [
      ( N.name,
        [
          Alcotest.test_case "scalar ring laws" `Quick t_scalar_ring;
          Alcotest.test_case "inversion" `Quick t_scalar_invert;
          Alcotest.test_case "batch inversion" `Quick t_scalar_invert_batch;
          Alcotest.test_case "scalar serialization" `Quick t_scalar_codec;
          Alcotest.test_case "identifiers" `Quick t_of_int;
          Alcotest.test_case "group laws" `Quick t_group_laws;
          Alcotest.test_case "small multiples" `Quick t_small_multiples;
          Alcotest.test_case "element serialization" `Quick t_element_codec;
          Alcotest.test_case "wipeable accumulator" `Quick t_accumulator;
        ] );
    ]
end
