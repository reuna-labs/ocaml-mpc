(** The prime-order group FROST is generic over, per RFC 9591 Section 3.1,
    together with the ciphersuite hash functions of Section 3.2.

    {1 Constant-time contract}

    Implementations must document, per operation, whether the running time
    depends on the {e value} of any argument. The protocol layers in this
    library rely on exactly two guarantees:

    - every {!SCALAR} operation is constant time in its arguments;
    - {!ELEMENT.scalar_mul_base} is constant time in its scalar.

    {!ELEMENT.scalar_mul} is {b permitted to be variable time}, and the protocol
    layers must only ever apply it to public scalars. This is not a concession:
    in FROST, arbitrary-point scalar multiplication is applied only to public
    values — the binding factors [rho_i], the participant identifiers [i^k] in
    share verification, the challenge [c] and Lagrange coefficient [lambda_i] in
    signature-share verification, and the challenge [c_l] in the DKG
    proof-of-knowledge check. The only secret-dependent operations in the whole
    protocol are scalar arithmetic and {e base-point} multiplication.

    That distinction is what makes FROST implementable on this tree's primitives
    with a defensible timing story, and it is enforced rather than believed:
    [Element.scalar_mul] has a small allowlist of call sites, each annotated
    with why its scalar is public, and CI fails on any use outside it. See
    [CONTRIBUTING.md]. *)

module type SCALAR = sig
  type t
  (** An element of [Z/qZ], [q] the group order. Values are always fully
      reduced. *)

  val zero : t
  val one : t
  val add : t -> t -> t
  val sub : t -> t -> t
  val mul : t -> t -> t
  val neg : t -> t

  val muladd : t -> t -> t -> t
  (** [muladd a b c] is [a * b + c]. Exposed because on edwards25519 this is the
      single native constant-time primitive and every other operation is derived
      from it; Horner evaluation and the Fermat inversion chain use it directly
      rather than paying for the derived {!add} and {!mul}. *)

  val invert : t -> (t, [> `Zero_scalar ]) result
  (** Constant time in the argument's value. *)

  val invert_batch : t array -> (t array, [> `Zero_scalar ]) result
  (** Montgomery's trick: one {!invert} plus [3(n-1)] multiplications, rather
      than [n] inversions. Used for Lagrange coefficients, where a coordinator
      needs [t] of them at once on the signature-share verification path. *)

  val equal : t -> t -> bool
  (** Constant time. *)

  val is_zero : t -> bool
  (** Constant time. *)

  val compare : t -> t -> int
  (** Numeric order, irrespective of the ciphersuite's serialization endianness.
      RFC 9591 requires the commitment list to be sorted by participant
      identifier, so the protocol needs an ordering; identifiers are public, and
      this is the only place it is used. {b Not} constant time, and not to be
      applied to secret scalars. *)

  val of_int : int -> (t, [> `Invalid_range ]) result
  (** Participant identifiers. Rejects values outside [[1, 65535]]: zero is not
      a valid identifier because [f(0)] is the shared secret itself, and the
      upper bound is the wire format's. *)

  val serialize : t -> string
  (** Exactly [ns] bytes, in the ciphersuite's endianness. *)

  val deserialize : string -> (t, [> `Invalid_length | `Invalid_range ]) result
  (** Rejects a wrong length and any encoding of a value [>= q]. *)

  val of_uniform_bytes : string -> (t, [> `Invalid_length ]) result
  (** Maps uniformly distributed bytes onto [Z/qZ] with negligible bias. This is
      what H1/H2/H3 are built from; the required input length is fixed by the
      ciphersuite. *)

  val random : Rand.t -> (t, [> `Rng_failure ]) result
  (** Uniform on [[1, q-1]]; never zero. Draws only from the supplied source. *)

  (** {2 Wipeable accumulation}

      Every operation above returns a fresh {!t}. For the Ed25519 ciphersuite
      that is an immutable [string], which OCaml cannot overwrite, so each
      secret intermediate — a Horner step in a polynomial evaluation, a partial
      sum of received shares, the running value of a signature share — becomes a
      copy that can only be dropped, never erased.

      An {!Acc.acc} is a mutable buffer instead. Operations write into it in
      place, so a computation over secrets allocates nothing and can be erased
      when it finishes.

      {b What this still does not give you.} {!Acc.reveal} materialises a {!t},
      and is named for that: the value escapes the wipeable buffer and is as
      unerasable as any other. OCaml's collector may also copy a buffer while
      promoting it, leaving a copy nothing can reach to overwrite. The honest
      claim is that this bounds the number of unerasable copies of a secret and
      erases the long-lived one — not that it reaches zero. *)

  module Acc : sig
    type acc
    (** A mutable scalar-sized buffer. *)

    val create : unit -> acc
    (** Zero. *)

    val of_scalar : t -> acc
    val set : acc -> t -> unit

    val reveal : acc -> t
    (** Materialise the value as a {!t}. See the caveat above: this is the point
        at which a secret leaves the buffer that can erase it. *)

    val muladd : dst:acc -> a:acc -> b:acc -> c:acc -> unit
    (** [dst <- a * b + c], in place and without allocating. Any of the four
        arguments may be the same buffer. *)

    val add : dst:acc -> acc -> unit
    (** [dst <- dst + x]. *)

    val wipe : acc -> unit
    (** Overwrite with zero. Idempotent. *)

    val wiped : acc -> bool
    (** Exposed so tests can assert erasure rather than assume it. *)
  end
end

module type ELEMENT = sig
  type scalar

  type t
  (** A group element, including the identity. An implementation over an affine
      Weierstrass point type must adjoin the identity explicitly. *)

  val identity : t
  val generator : t

  val add : t -> t -> t
  (** Total: no exceptional cases, including doubling and the identity. *)

  val sub : t -> t -> t
  val neg : t -> t

  val scalar_mul : scalar -> t -> t
  (** [scalar_mul s p] is [s * p]. {b May be variable time in [s]}; call sites
      must pass public scalars only. See the constant-time contract above. *)

  val scalar_mul_base : scalar -> t
  (** [scalar_mul_base s] is [s * generator]. {b Must be constant time in [s]}.
      This is the only operation the protocol applies to a secret scalar. *)

  val equal : t -> t -> bool
  val is_identity : t -> bool

  val serialize : t -> string
  (** Exactly [ne] bytes. *)

  val deserialize :
    string ->
    ( t,
      [> `Invalid_length
      | `Invalid_format
      | `Not_on_curve
      | `At_infinity
      | `Low_order ] )
    result
  (** Enforces, in order: exact length; canonical encoding; on-curve; not the
      identity; and membership of the prime-order subgroup. RFC 9591 Section 6.1
      requires all five for FROST(Ed25519, SHA-512), and an implementation that
      skips the last two accepts points that break the security argument. *)
end

module type CIPHERSUITE = sig
  val id : string
  (** The RFC 9591 context string, e.g. ["FROST-ED25519-SHA512-v1"]. *)

  val ns : int
  (** Serialized scalar length in bytes. *)

  val ne : int
  (** Serialized element length in bytes. *)

  val nh : int
  (** Hash output length in bytes. *)

  val suite_tag : int
  (** A single byte identifying this suite on our wire format. Ours, not the
      RFC's. *)

  module Scalar : SCALAR
  module Element : ELEMENT with type scalar = Scalar.t

  (** {1 RFC 9591 Section 3.2 hashes} *)

  val h1 : string -> Scalar.t
  (** Binding factor, [rho]. *)

  val h2 : string -> Scalar.t
  (** Challenge, [c]. For suites whose signatures must verify under a
      pre-existing standard verifier — Ed25519 under RFC 8032 — this
      deliberately carries {e no} context string, so that the challenge is
      exactly the one that verifier computes. *)

  val h3 : string -> Scalar.t
  (** Nonce generation. *)

  val h4 : string -> string
  (** Message hash, [nh] bytes. *)

  val h5 : string -> string
  (** Commitment-list hash, [nh] bytes. *)

  val hdkg : string -> Scalar.t
  (** Challenge hash for the Appendix D DKG proof of knowledge. RFC 9591 does
      not specify this and publishes no vectors for it; see [CONTRIBUTING.md]
      for the construction this library pins and its interoperability
      consequences. *)
end

module type CIPHERSUITE_CT = sig
  include CIPHERSUITE

  (** A ciphersuite whose {!ELEMENT.scalar_mul} is {b also} constant time.

      FROST does not need this. Threshold ECDSA does: it multiplies arbitrary
      points by secret scalars. Requiring this signature in the ECDSA functor
      makes it a {e type error} to instantiate threshold ECDSA over a
      variable-time curve implementation. The distinction costs nothing today
      and cannot be retrofitted cheaply later. *)
end
