(** FROST(secp256k1, SHA-256), RFC 9591 Section 6.5.

    The suite Bitcoin and Ethereum custody needs — and the one that stresses the
    group abstraction hardest, because almost nothing about it resembles
    Ed25519: a short Weierstrass curve rather than twisted Edwards, big-endian
    scalars rather than little-endian, 33-byte compressed points rather than 32,
    and a scalar field close enough to a power of two that scalars must be
    derived with RFC 9380 [hash_to_field] rather than by reducing a wide hash.

    {1 Constant-time audit}

    Built on {!Mirage_crypto_ec.P256k1.Primitive} rather than on
    [Mirage_crypto_blockchain.Secp256k1]. Both implement the same group; the
    latter is plain zarith double-and-add and says so in its own documentation,
    which makes it unusable for a secret key share.

    {v
    operation                    realisation                                timing
    -------------------------------------------------------------------------------
    Scalar.add / mul / neg       fiat-crypto n-field, branch free           CT
    Scalar.invert                Bernstein-Yang, fixed iteration count      CT
    Scalar.muladd                mul then add                              CT
    Scalar.Acc.*                 the *_into variants, into owned bytes      CT
    Scalar.of_uniform_bytes      hash_to_field: two halves, one mul, one add CT
    Scalar.deserialize           length plus constant-time range compare    CT
    Element.scalar_mul_base      fixed_smul_cmb (comb, selectznz lookups)   CT
    Element.scalar_mul           var_smul_rwnaf (regular wNAF)              CT in the scalar
    Element.add                  complete RCB formula                       branch free
    Element.deserialize          SEC1 decode, decompression                 vartime
    Element.serialize            compressed SEC1                            vartime
    v}

    Unlike the Ed25519 suite, {!Mpc.Group.ELEMENT.scalar_mul} here {e is}
    constant time in its scalar, so this module satisfies
    {!Mpc.Group.CIPHERSUITE_CT} — which is what a future threshold-ECDSA
    construction will require, since that multiplies arbitrary points by secret
    scalars.

    The usual caveat still applies: this is a source-level property of the
    underlying fiat-crypto and ECCKiila code, not a measurement of the compiled
    binary, and OCaml itself offers no constant-time guarantees. See the README.
*)

module Suite : Mpc.Group.CIPHERSUITE_CT
