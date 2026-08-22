(** Trusted-dealer key generation, RFC 9591 Appendix C.

    {b A dealer knows the whole signing key.} That is the opposite of what this
    library is for, and this module exists for two narrow purposes: replaying
    the RFC's test vectors, which are all dealer-generated, and migrating an
    existing key into the scheme. Production key generation is
    {!Mpc_frost.Keygen}, the two-round Pedersen DKG, in which the full key never
    exists anywhere. *)

module Make (C : Mpc.Group.CIPHERSUITE) : sig
  module V : module type of Mpc.Vss.Make (C)

  type key_package = {
    id : C.Scalar.t;
    share : C.Scalar.t;  (** {b secret}: this participant's signing share *)
    verification_share : C.Element.t;
    group_public_key : C.Element.t;
    threshold : int;
  }

  type public_key_package = {
    pk : C.Element.t;
    commitment : V.t;
    verification_shares : (C.Scalar.t * C.Element.t) list;
  }

  val generate :
    Mpc.Rand.t ->
    secret:C.Scalar.t ->
    threshold:int ->
    ids:C.Scalar.t list ->
    ( key_package list * public_key_package,
      [> `Bad_threshold | `Duplicate_id | `Zero_id | `Rng_failure ] )
    result
  (** The dealer's polynomial is wiped before returning; see the caveat on
      {!Mpc.Shamir.Make.wipe} about what wiping an abstract scalar can and
      cannot do. *)

  val of_coefficients :
    coefficients:C.Scalar.t array ->
    ids:C.Scalar.t list ->
    ( key_package list * public_key_package,
      [> `Bad_threshold | `Duplicate_id | `Zero_id ] )
    result
  (** Deterministic variant for test vectors, which fix every coefficient. *)
end
