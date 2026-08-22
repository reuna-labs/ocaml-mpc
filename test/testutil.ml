(** Shared test fixtures, functorised over the ciphersuite.

    Every suite that exercises arithmetic or the protocol is a functor over
    {!Mpc.Group.CIPHERSUITE} and gets instantiated once per ciphersuite, so
    adding a curve adds an instantiation rather than a copy of the tests. That
    is also the point: a test suite that only ever runs against one instance
    does not demonstrate that the abstraction is generic, it just demonstrates
    that one implementation works.

    Every test supplies its own seeded generator, so no ambient RNG is consulted
    and a whole run is reproducible from its seeds. *)

let hex = Ohex.encode

let rand_of_seed seed =
  let g =
    Mirage_crypto_rng.create ~strict:true ~seed
      (module Mirage_crypto_rng.Hmac_drbg (Digestif.SHA256))
  in
  Mpc.Rand.v (fun n -> Mirage_crypto_rng.generate ~g n)

module Make (C : Mpc.Group.CIPHERSUITE) = struct
  module Sc = C.Scalar
  module El = C.Element

  let hex = hex
  let rand_of_seed = rand_of_seed

  let sc : Sc.t Alcotest.testable =
    Alcotest.testable
      (fun ppf s -> Format.pp_print_string ppf (hex (Sc.serialize s)))
      Sc.equal

  let el : El.t Alcotest.testable =
    Alcotest.testable
      (fun ppf p -> Format.pp_print_string ppf (hex (El.serialize p)))
      El.equal

  let some_scalars n seed =
    let r = rand_of_seed seed in
    List.init n (fun _ -> Result.get_ok (Sc.random r))

  let id n = Result.get_ok (Sc.of_int n)
  let ids n = List.init n (fun i -> id (i + 1))
end

module Ed25519 = Make (Mpc_ed25519.Suite)
(** The Ed25519 instantiation, for suites that are not (yet) functorised.

    Protocol machinery — the session state machine, fault injection, the wire
    codec — is the same logic whatever the curve, so running it twice buys
    little. Anything that exercises {e arithmetic} is functorised instead and
    runs against every ciphersuite; see {!Suites_ed25519}. *)
