(** FROST two-round signing, RFC 9591 Section 5.

    Pure, state-free functions named exactly as the RFC names them, so that a
    known-answer test reads as a transcript of the specification and review
    against it is mechanical. The state machines in {!Mpc_frost.Sign} and
    {!Mpc_frost.Keygen} are built on top; nothing here holds state or decides
    policy. *)

module Make (C : Mpc.Group.CIPHERSUITE) : sig
  module E : module type of Encoding.Make (C)
  module Sh : module type of Mpc.Shamir.Make (C)

  type nonces = {
    hiding : C.Scalar.t;  (** {b secret}, single use *)
    binding : C.Scalar.t;  (** {b secret}, single use *)
  }

  val nonce_generate :
    Mpc.Rand.t -> secret:C.Scalar.t -> (C.Scalar.t, [> `Rng_failure ]) result
  (** [H3(random(32) || SerializeScalar(secret))]. Hedged: the signing share is
      hashed in, so a repeated draw from the randomness source cannot collide
      across different keys. This does {b not} prevent reuse of a generated
      nonce — only the linear lifetime enforced by {!Mpc_frost.Sign} does that.
  *)

  val commit :
    Mpc.Rand.t ->
    secret:C.Scalar.t ->
    (nonces * E.commitment, [> `Rng_failure ]) result
  (** Round 1. The caller must treat the returned {!nonces} as single use.
      Prefer {!Mpc_frost.Sign}, which makes reuse structurally impossible. *)

  val binding_factors :
    group_public_key:C.Element.t ->
    commitment_list:E.commitment_list ->
    msg:string ->
    (C.Scalar.t * C.Scalar.t) list
  (** [(identifier, rho)] pairs, in commitment-list order. *)

  val group_commitment :
    commitment_list:E.commitment_list ->
    binding_factors:(C.Scalar.t * C.Scalar.t) list ->
    C.Element.t
  (** [R = sum_i (D_i + rho_i * E_i)]. *)

  val challenge :
    group_commitment:C.Element.t ->
    group_public_key:C.Element.t ->
    msg:string ->
    C.Scalar.t

  val sign :
    id:C.Scalar.t ->
    share:C.Scalar.t ->
    group_public_key:C.Element.t ->
    nonces:nonces ->
    msg:string ->
    commitment_list:E.commitment_list ->
    ( C.Scalar.t,
      [> `Not_a_participant | `Duplicate_id | `Zero_id | `Zero_scalar ] )
    result
  (** Round 2. [z_i = d_i + e_i * rho_i + lambda_i * s_i * c]. *)

  val aggregate : group_commitment:C.Element.t -> C.Scalar.t list -> string

  val verify_signature_share :
    id:C.Scalar.t ->
    verification_share:C.Element.t ->
    sig_share:C.Scalar.t ->
    commitment_list:E.commitment_list ->
    binding_factors:(C.Scalar.t * C.Scalar.t) list ->
    group_public_key:C.Element.t ->
    msg:string ->
    ( unit,
      [> `Bad_share
      | `Not_a_participant
      | `Duplicate_id
      | `Zero_id
      | `Zero_scalar ] )
    result
  (** Checks one participant's contribution in isolation, so a failed
      aggregation names the party responsible instead of yielding an opaque
      invalid signature. *)

  val verify : group_public_key:C.Element.t -> msg:string -> string -> bool
  (** [z * G = R + c * PK]. For FROST(Ed25519, SHA-512) an accepted signature is
      also accepted by any RFC 8032 verifier; the test suite checks exactly that
      against {!Mirage_crypto_ec.Ed25519.verify}. *)
end
