(** Errors returned across the library.

    Every fallible operation returns [(_, t) result] or [(_, [< t ]) result]; no
    exception crosses a public boundary. The type is a polymorphic variant so
    that individual modules can expose the narrower subset they actually produce
    while still coercing into this union. The shape follows {!Bitcoin.Error} in
    the sibling ocaml-bitcoin project, and the encoding subset is deliberately
    identical so the two compose without translation. *)

type t =
  [ (* decoding *)
    `Eof of int
    (** wanted this many more bytes than were available *)
  | `Trailing of int
    (** this many bytes left unconsumed after a complete parse *)
  | `Invalid_length
  | `Invalid_format
  | `Invalid_range
  | (* group *)
    `Not_on_curve
  | `At_infinity
  | `Low_order  (** valid point, but outside the prime-order subgroup *)
  | `Zero_scalar  (** a scalar required to be invertible was zero *)
  | (* sharing *)
    `Bad_threshold
  | `Duplicate_id
  | `Zero_id
  | `Not_a_participant
  | `Length_mismatch
  | `Bad_share
  | `Bad_proof
  | (* session *)
    `Wrong_session
  | `Wrong_round
  | `Unknown_peer
  | `Equivocation
  | `Nonce_already_used
  | `Rng_failure
  | `Unsealed_private_payload
  | `Msg of string ]

val pp : Format.formatter -> [< t ] -> unit
val to_string : [< t ] -> string
