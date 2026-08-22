(** The {b normative} byte encodings of RFC 9591 — the ones that feed the hash
    functions.

    These are deliberately {e not} the wire format. The wire format
    ({!Mpc_frost.Msg}) is ours and may change; these encodings are fixed by the
    RFC and changing one silently produces signatures that no other
    implementation accepts. Conflating the two is the most common
    interoperability bug in FROST implementations, so they live in separate
    modules with separate tests and share no helpers. *)

module Make (C : Mpc.Group.CIPHERSUITE) : sig
  type commitment = { hiding : C.Element.t; binding : C.Element.t }

  type commitment_list = (C.Scalar.t * commitment) list
  (** Ascending by identifier, no duplicates. Use {!commitment_list} to build
      one. *)

  val commitment_list :
    (C.Scalar.t * commitment) list ->
    (commitment_list, [> `Duplicate_id | `Zero_id ]) result
  (** Sorts and validates. *)

  val participants : commitment_list -> C.Scalar.t list

  val encode_identifier : C.Scalar.t -> string
  (** [SerializeScalar]. *)

  val encode_commitment_list : commitment_list -> string
  (** RFC 9591 [encode_group_commitment_list]:
      [SerializeScalar(id) || SerializeElement(hiding) ||
       SerializeElement(binding)], concatenated in ascending identifier order.
  *)

  val binding_factor_input :
    group_public_key:C.Element.t ->
    commitment_list:commitment_list ->
    msg:string ->
    C.Scalar.t ->
    string
  (** [SerializeElement(PK) || H4(msg) || H5(encode_group_commitment_list(L)) ||
       EncodeIdentifier(i)].

      The group public key was added to this input by RFC 9591 relative to
      earlier drafts of FROST; omitting it interoperates with nothing. *)

  val challenge_input :
    group_commitment:C.Element.t ->
    group_public_key:C.Element.t ->
    msg:string ->
    string
  (** [SerializeElement(R) || SerializeElement(PK) || msg]. For Ed25519, H2 of
      this is exactly the RFC 8032 challenge. *)

  val signature : r:C.Element.t -> z:C.Scalar.t -> string
  (** [SerializeElement(R) || SerializeScalar(z)]. For Ed25519 this is a stock
      RFC 8032 signature. *)

  val parse_signature :
    string ->
    (C.Element.t * C.Scalar.t, [> `Invalid_length | Mpc.Error.t ]) result
end
