(** The randomness capability.

    A source of randomness is a {e function}, not a dependency. The protocol
    core cannot name [Mirage_crypto_rng.default_generator], so it cannot raise
    [No_default_generator] inside a unikernel that forgot to initialise it: the
    compiler asks for the source instead. No entry point in this library takes
    an optional [?rand] with a default; every one that consumes randomness takes
    it positionally.

    In production:
    {[
      Mirage_crypto_rng_mirage.initialize (module Mirage_crypto_rng.Fortuna);
      let rand = Mpc.Rand.v Mirage_crypto_rng.generate in
      ...
    ]}

    In tests, one seed per party over an HMAC-DRBG makes an entire n-party run
    reproducible; see [test/sim]. *)

type t

val v : (int -> string) -> t
(** [v f] wraps a generator, where [f n] must return exactly [n] uniformly
    distributed bytes. A source that returns the wrong length is a programming
    error in the caller, reported as {!Error.t}[.`Rng_failure] at the session
    boundary rather than silently weakening a key. *)

val bytes : t -> int -> (string, [> `Rng_failure ]) result
(** [bytes t n] draws [n] bytes. Fails if [n] is negative or the underlying
    source returns the wrong number of bytes. *)

val bytes_exn : t -> int -> string
(** As {!bytes}, for internal use on paths already wrapped by a
    [result]-returning boundary.

    @raise Failure if the source misbehaves. *)
