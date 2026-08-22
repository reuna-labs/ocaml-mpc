(* Timing measurements for the operations FROST applies to secret scalars.

   The constant-time claim in the README rests on an argument -- that the only
   secret-dependent operations are scalar arithmetic and base-point multiplication, and
   that both are constant time in the underlying C -- plus a lint that keeps the
   argument true as the code changes. This adds measurement to the argument. It does
   not replace it, and it is much weaker than either verification or an instrumented
   run under valgrind; see dudect.mli for exactly what it can and cannot show. *)

module Suite = Mpc_ed25519.Suite
module Sc = Suite.Scalar
module El = Suite.Element

let rand = Mpc.Rand.v Mirage_crypto_rng.generate
let random_scalar () = Sc.serialize (Result.get_ok (Sc.random rand))

(* The fixed class is all zeroes rather than a random-but-fixed value: it is the input
   most likely to take a short path through an implementation that has one. *)
let fixed = String.make 32 '\000'
let of_octets s = match Sc.deserialize s with Ok x -> x | Error _ -> Sc.zero
let sink = ref Sc.zero
let esink = ref El.identity

let () =
  Mirage_crypto_rng_unix.use_default ();
  print_endline
    "ocaml-mpc timing measurements -- FROST(Ed25519, SHA-512)\n\
     Operations applied to SECRET scalars must not show input-dependent timing.\n";
  let outcome =
    Dudect.run ~samples:1200
      ~rounds:5
        (* The positive control is Element.scalar_mul, which is documented as variable
         time: it routes through ge_double_scalarmult_vartime. If the harness cannot
         see leakage here, it cannot be trusted to see it anywhere. *)
      ~control:
        ( "Element.scalar_mul (known variable time)",
          fixed,
          random_scalar,
          fun s -> esink := El.scalar_mul (of_octets s) El.generator )
      [
        ( "Scalar.muladd  (secret, hot path)",
          fixed,
          random_scalar,
          fun s ->
            let x = of_octets s in
            sink := Sc.muladd x x x );
        ( "Scalar.mul",
          fixed,
          random_scalar,
          fun s ->
            let x = of_octets s in
            sink := Sc.mul x x );
        ( "Scalar.add",
          fixed,
          random_scalar,
          fun s ->
            let x = of_octets s in
            sink := Sc.add x x );
        (* Two fixed classes for inversion. Zero is the input an implementation is
           most likely to special-case -- an early return there was exactly what the
           first run of this harness found -- and a fixed non-zero value tests the
           chain itself rather than the special case. *)
        ( "Scalar.invert vs zero",
          fixed,
          random_scalar,
          fun s ->
            sink := Result.value ~default:Sc.zero (Sc.invert (of_octets s)) );
        ( "Scalar.invert vs fixed non-zero",
          Sc.serialize Sc.one,
          random_scalar,
          fun s ->
            sink := Result.value ~default:Sc.zero (Sc.invert (of_octets s)) );
        ( "Element.scalar_mul_base (secret)",
          fixed,
          random_scalar,
          fun s -> esink := El.scalar_mul_base (of_octets s) );
        ( "Scalar.equal (Eqaf)",
          fixed,
          random_scalar,
          fun s -> ignore (Sc.equal (of_octets s) Sc.one) );
      ]
  in
  Format.printf "%a@." Dudect.pp_outcome outcome;
  (* Exit non-zero on a detected leak so this can gate a release, but not on
     INCONCLUSIVE: that is a statement about the measurement environment, and failing
     a build because a laptop was busy would teach people to ignore the result. *)
  let leaked =
    List.exists (fun (_, v) -> v.Dudect.leaked) outcome.Dudect.results
  in
  if leaked then exit 1
