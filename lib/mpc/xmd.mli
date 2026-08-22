(** RFC 9380 [expand_message_xmd] and [hash_to_field].

    The Ed25519 ciphersuite maps bytes to scalars by hashing to 64 bytes and
    reducing: the modulus is close enough to a power of two that the bias is
    negligible. The secp256k1 and P-256 ciphersuites cannot do that — their
    group orders sit just below 2^256, so reducing a 256-bit hash is measurably
    biased — and RFC 9591 specifies {!hash_to_field} for them instead.

    This is where the two ciphersuites genuinely diverge, so it lives in the
    core rather than in either one. *)

val expand_message_xmd :
  hash:(string -> string) ->
  block_size:int ->
  digest_size:int ->
  dst:string ->
  msg:string ->
  len:int ->
  (string, [> `Invalid_length ]) result
(** RFC 9380 Section 5.3.1. [block_size] is the hash's internal block size — 64
    for SHA-256 — and [digest_size] its output length.

    A [dst] longer than 255 bytes is replaced by
    [H("H2C-OVERSIZE-DST-" || dst)], as the specification requires; the length
    prefix that follows is a single byte, so an unhashed long [dst] would not be
    unambiguous.

    Fails if [len] exceeds 255 * [digest_size], the point beyond which the
    one-byte counter would wrap. *)
