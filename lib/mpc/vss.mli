(** Feldman verifiable secret sharing.

    A dealer publishes [phi_k = a_k * G] for each coefficient of its polynomial.
    Any recipient can then check its own share against that commitment without
    learning anything about the other shares, which is what makes the DKG's
    identifiable abort possible: a bad share is attributable to the party that
    sent it. *)

module Make (C : Group.CIPHERSUITE) : sig
  module S : module type of Shamir.Make (C)

  type t = C.Element.t array
  (** {b Public.} [phi_k = a_k * G] for [k] in [0, t-1]. *)

  val commit : S.poly -> t
  (** One {!Group.ELEMENT.scalar_mul_base} per coefficient — constant time, and
      the only place a secret scalar meets the group. *)

  val secret_commitment : t -> C.Element.t
  (** [phi_0 = secret * G]. For a completed DKG this is the group public key. *)

  val threshold : t -> int

  val verify_share : t -> S.share -> (unit, [> `Bad_share ]) result
  (** Checks [share.value * G = sum_k share.id^k * phi_k], evaluated by Horner
      in the exponent. The left side is a base-point multiplication of a secret
      scalar (constant time); the right side multiplies public commitments by
      the public identifier. *)

  val combine : t list -> (t, [> `Length_mismatch | `Bad_threshold ]) result
  (** Coefficient-wise sum. In the DKG this yields the commitment to the joint
      polynomial, whose [phi_0] is the group public key. *)

  val participant_public_key :
    t list ->
    id:C.Scalar.t ->
    (C.Element.t, [> `Length_mismatch | `Bad_threshold ]) result
  (** [Y_i = s_i * G] derived from the combined commitments alone, so a
      coordinator can verify a signature share without ever seeing [s_i]. *)

  val serialize : t -> string
  val deserialize : threshold:int -> string -> (t, Error.t) result
end
