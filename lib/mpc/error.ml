type t =
  [ `Eof of int
  | `Trailing of int
  | `Invalid_length
  | `Invalid_format
  | `Invalid_range
  | `Not_on_curve
  | `At_infinity
  | `Low_order
  | `Zero_scalar
  | `Bad_threshold
  | `Duplicate_id
  | `Zero_id
  | `Not_a_participant
  | `Length_mismatch
  | `Bad_share
  | `Bad_proof
  | `Wrong_session
  | `Wrong_round
  | `Unknown_peer
  | `Equivocation
  | `Nonce_already_used
  | `Rng_failure
  | `Unsealed_private_payload
  | `Msg of string ]

let to_string : [< t ] -> string = function
  | `Eof n -> Printf.sprintf "unexpected end of input: wanted %d more byte(s)" n
  | `Trailing n -> Printf.sprintf "%d trailing byte(s) after a complete parse" n
  | `Invalid_length -> "invalid length"
  | `Invalid_format -> "invalid format"
  | `Invalid_range -> "value out of range"
  | `Not_on_curve -> "point is not on the curve"
  | `At_infinity -> "point is the identity"
  | `Low_order -> "point is outside the prime-order subgroup"
  | `Zero_scalar -> "scalar is zero and has no inverse"
  | `Bad_threshold -> "invalid threshold"
  | `Duplicate_id -> "duplicate participant identifier"
  | `Zero_id -> "participant identifier is zero"
  | `Not_a_participant -> "identifier is not in the participant set"
  | `Length_mismatch -> "length mismatch"
  | `Bad_share -> "share does not verify against its commitment"
  | `Bad_proof -> "proof does not verify"
  | `Wrong_session -> "message belongs to a different session"
  | `Wrong_round -> "message belongs to a round outside this protocol"
  | `Unknown_peer -> "message from a peer outside the participant set"
  | `Equivocation -> "peer sent two different messages for the same round"
  | `Nonce_already_used -> "signing nonce has already been used and was erased"
  | `Rng_failure -> "the supplied randomness source misbehaved"
  | `Unsealed_private_payload ->
      "a private payload was encoded without a seal function"
  | `Msg m -> m

let pp ppf e = Format.pp_print_string ppf (to_string e)
