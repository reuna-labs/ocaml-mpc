(** Shamir secret sharing over an abstract prime-order group's scalar field.

    A secret [s] is shared as [f(0)] of a degree-[t-1] polynomial; any [t]
    evaluations reconstruct it and any [t-1] reveal nothing. Identifiers are
    non-zero scalars, since [f(0)] is the secret itself. *)

module Make (C : Group.CIPHERSUITE) : sig
  type poly
  (** {b Secret.} The coefficients [a_0 .. a_{t-1}], with [a_0] the shared
      secret. *)

  type share = {
    id : C.Scalar.t;  (** public, non-zero *)
    value : C.Scalar.t;  (** {b secret} *)
  }

  val random :
    Rand.t ->
    degree:int ->
    secret:C.Scalar.t ->
    (poly, [> `Bad_threshold | `Rng_failure ]) result
  (** A polynomial with [a_0 = secret] and the remaining [degree] coefficients
      drawn uniformly from the supplied source. *)

  val of_coefficients : C.Scalar.t array -> (poly, [> `Bad_threshold ]) result
  (** For replaying test vectors, which fix the coefficients. *)

  val degree : poly -> int

  (** {2 Accessors}

      All of these raise [Invalid_argument] once {!wipe} has been called. *)

  val coeff : poly -> int -> C.Scalar.t
  val secret : poly -> C.Scalar.t
  val coefficients : poly -> C.Scalar.t array

  val eval : poly -> C.Scalar.t -> C.Scalar.t
  (** Horner, over {!Group.SCALAR.muladd}. *)

  val wipe : poly -> unit
  (** Overwrite the polynomial's coefficients with zero. Idempotent.

      Unlike a bare array of scalars, this really does erase: the coefficients
      are held in one contiguous {!Secret.t}, which owns mutable bytes. It is
      the durable secret in a distributed key generation — it lives for the
      whole of round 1 — and it is the one worth erasing.

      {b Two limits, stated because a wipe that is believed to do more than it
         does is worse than none.} Reads through {!eval} and {!coeff}
      deserialise via [C.Scalar.t], which for the Ed25519 suite is an immutable
      string, so each read leaves a transient copy that cannot be overwritten
      and survives until collection. And the scalars handed to
      {!of_coefficients} or produced by [Scalar.random] inside {!random} are
      themselves strings the caller cannot erase. Closing either needs the group
      abstraction to expose [scalar_muladd_into]-style operations writing into
      caller-owned buffers; the mirage-crypto fork now provides them, but
      {!Group} does not yet surface them. See [CONTRIBUTING.md].

      Every accessor raises [Invalid_argument] after a wipe, so a use-after-wipe
      is a loud failure rather than a silently wrong signature. *)

  val split :
    Rand.t ->
    secret:C.Scalar.t ->
    threshold:int ->
    ids:C.Scalar.t list ->
    ( share list * poly,
      [> `Bad_threshold | `Duplicate_id | `Zero_id | `Rng_failure ] )
    result
  (** The caller owns the returned [poly] and must {!wipe} it once the Feldman
      commitment has been taken. *)

  val shares_of_poly :
    poly ->
    ids:C.Scalar.t list ->
    (share list, [> `Duplicate_id | `Zero_id ]) result

  val lagrange :
    ids:C.Scalar.t list ->
    id:C.Scalar.t ->
    ( C.Scalar.t,
      [> `Not_a_participant | `Duplicate_id | `Zero_id | `Zero_scalar ] )
    result
  (** RFC 9591 [derive_interpolating_value]. Every input is public. One modular
      inversion, of the accumulated denominator, rather than one per factor. *)

  val lagrange_all :
    ids:C.Scalar.t list ->
    (C.Scalar.t list, [> `Duplicate_id | `Zero_id | `Zero_scalar ]) result
  (** Every coefficient for the set at once, via {!Group.SCALAR.invert_batch}:
      one inversion in total rather than one per participant. This is the
      signature-share verification path, which runs once per participant per
      signing round. *)

  val interpolate_secret :
    share list ->
    ( C.Scalar.t,
      [> `Duplicate_id | `Zero_id | `Zero_scalar | `Bad_threshold ] )
    result
  (** Reconstructs [f(0)]. Reconstruction defeats the purpose of threshold
      signing and exists for tests and for migrating a key out of the scheme. *)

  val interpolate_element :
    (C.Scalar.t * C.Element.t) list ->
    ( C.Element.t,
      [> `Duplicate_id | `Zero_id | `Zero_scalar | `Bad_threshold ] )
    result
  (** The same interpolation in the exponent. Public data only. *)
end
