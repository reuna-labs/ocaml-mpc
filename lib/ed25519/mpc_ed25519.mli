(** FROST(Ed25519, SHA-512), RFC 9591 Section 6.1.

    {1 Why this suite ships first}

    In FROST, arbitrary-point scalar multiplication is applied only to
    {e public} scalars; the only secret-dependent operations are scalar
    arithmetic and {e base-point} multiplication. On edwards25519 both of those
    are already constant time in this tree — [sc_muladd] and
    [x25519_ge_scalarmult_base], both from BoringSSL — so this suite needs no
    new constant-time code. It also needs no bignum, hence no zarith and no GMP,
    so an Ed25519-only unikernel avoids the [ocaml-gmp] duniverse apparatus
    entirely. And because H2 carries no context string, the aggregated signature
    is an ordinary RFC 8032 signature: {!Mirage_crypto_ec.Ed25519.verify} is a
    free, fully independent verification oracle.

    {1 Constant-time audit}

    Every operation, and where its timing behaviour comes from. This table is
    the library's constant-time claim; it is maintained as part of the source,
    and the [scalar_mul] allowlist lint in CI is what keeps it true.

    {v
    operation                  realisation                                     timing
    ---------------------------------------------------------------------------------
    Scalar.mul a b             scalar_muladd a b zero                          CT
    Scalar.add a b             scalar_muladd a one b                           CT
    Scalar.neg a               scalar_muladd a (L-1) zero                      CT
    Scalar.sub a b             scalar_muladd b (L-1) a                         CT
    Scalar.muladd              native sc_muladd                                CT
    Scalar.invert a            a^(L-2), fixed public addition chain over mul   CT in a
    Scalar.invert_batch        Montgomery trick over mul + one invert          CT
    Scalar.of_uniform_bytes    scalar_reduce (64 bytes in)                     CT
    Scalar.deserialize         length check + branch-free LE compare < L       CT
    Scalar.equal / is_zero     Eqaf.equal                                      CT
    Element.scalar_mul_base    scalar_mult_base (ge_scalarmult_base)           CT
    Element.add                point_add                                       vartime decode
    Element.neg                sign-bit flip, identity special-cased            CT
    Element.scalar_mul k P     verify_double_base ~k:(neg k) ~pub:P ~s:zero    VARTIME
    Element.deserialize        canonicity, point_valid, identity, torsion      vartime
    v}

    [Element.scalar_mul] is variable time. It is applied to public scalars only;
    see the contract in {!Mpc.Group}.

    {1 Limits of the guarantee}

    OCaml offers no constant-time guarantees of its own. {!Mpc.Secret} protects
    the durable secrets — the signing share, the nonce between rounds, the DKG
    polynomial — because it owns wipeable [bytes]. It cannot reach the transient
    immutable [string] that a C stub allocates for its result, nor copies the GC
    has moved. Do not read more into the table above than it says. *)

module Suite : Mpc.Group.CIPHERSUITE
(** {b Deliberately not} {!Mpc.Group.CIPHERSUITE_CT}. [Element.scalar_mul] here
    routes through [ge_double_scalarmult_vartime] and is variable time, which
    FROST tolerates because it only ever applies it to public scalars. Threshold
    ECDSA does not tolerate it, and the [CIPHERSUITE_CT] functor argument is
    precisely what makes passing this module to an ECDSA construction a compile
    error rather than a silent key leak. *)
