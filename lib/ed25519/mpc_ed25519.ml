(* FROST(Ed25519, SHA-512), RFC 9591 Section 6.1.

   Scalars are 32-byte little-endian values mod L; elements are 32-byte RFC 8032
   encodings. See the audit table in the .mli before changing anything here. *)

module P = Mirage_crypto_ec.Ed25519.Primitive

let of_hex h =
  let n = String.length h / 2 in
  String.init n (fun i ->
      Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

(* Group order L = 2^252 + 27742317777372353535851937790883648493, little-endian. *)
let l_le =
  of_hex "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"

(* Field prime p = 2^255 - 19, little-endian. Used only for the canonicity check on
   point encodings, which mirage-crypto's fe_frombytes does not perform. *)
let p_le =
  of_hex "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"

let zero32 = String.make 32 '\000'
let one32 = "\001" ^ String.make 31 '\000'

(* L-1 and L-2, little-endian. Negation is multiplication by L-1; inversion is
   exponentiation to L-2. Both exponents/multipliers are public constants. *)
let l_minus_1 =
  of_hex "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"

let l_minus_2 =
  of_hex "ebd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"

(* Branch-free "is [s] strictly less than the 32-byte little-endian [m]?": compute
   s - m with borrow propagation and report the final borrow. OCaml ints are 63-bit,
   so for d in [-256, 255] the expression (d lsr 62) land 1 is 1 exactly when d < 0. *)
let lt_le s m =
  let borrow = ref 0 in
  for i = 0 to 31 do
    let d =
      Char.code (String.unsafe_get s i)
      - Char.code (String.unsafe_get m i)
      - !borrow
    in
    borrow := (d lsr 62) land 1
  done;
  !borrow = 1

let sha512 s = Digestif.SHA512.(to_raw_string (digest_string s))
let context_string = "FROST-ED25519-SHA512-v1"

module Scalar = struct
  type t = string (* 32 bytes, little-endian, reduced mod L *)

  let zero = zero32
  let one = one32
  let muladd a b c = P.scalar_muladd a b c
  let mul a b = muladd a b zero
  let add a b = muladd a one b
  let neg a = muladd a l_minus_1 zero
  let sub a b = muladd b l_minus_1 a
  let equal = Eqaf.equal
  let is_zero a = Eqaf.equal a zero

  (* Little-endian, so compare from the most significant byte down. Public data only. *)
  let compare a b =
    let rec go i =
      if i < 0 then 0
      else
        let d = Char.code a.[i] - Char.code b.[i] in
        if d <> 0 then d else go (i - 1)
    in
    go 31

  let serialize t = t

  let deserialize s =
    if String.length s <> 32 then Error `Invalid_length
    else if not (lt_le s l_le) then Error `Invalid_range
    else Ok s

  let of_uniform_bytes s =
    if String.length s <> 64 then Error `Invalid_length
    else Ok (P.scalar_reduce s)

  let of_int n =
    if n < 1 || n > 0xffff then Error `Invalid_range
    else
      Ok
        (String.init 32 (fun i ->
             if i = 0 then Char.chr (n land 0xff)
             else if i = 1 then Char.chr ((n lsr 8) land 0xff)
             else '\000'))

  (* a^(L-2) by square-and-multiply, most significant bit first. The exponent is a
     public constant, so branching on its bits leaks nothing; every multiplication is
     the constant-time sc_muladd. Bit 252 of L-2 is set and bits above it are clear. *)
  let invert a =
    (* The chain runs unconditionally, including for zero. An early return on zero
       would make the running time depend on whether the input is zero -- which the
       timing harness in test/timing measures at |t| > 200 -- and while this library
       only ever inverts public values (Lagrange denominators), an operation that
       leaks a property of its input is not one to leave lying around. 0^(L-2) is 0,
       so the chain is correct for zero too; only the returned constructor differs,
       and both branches return immediately. *)
    let acc = ref one in
    for i = 252 downto 0 do
      acc := mul !acc !acc;
      let bit = (Char.code l_minus_2.[i / 8] lsr (i mod 8)) land 1 in
      if bit = 1 then acc := mul !acc a
    done;
    if is_zero a then Error `Zero_scalar else Ok !acc

  (* Montgomery's trick: one inversion plus 3(n-1) multiplications. *)
  let invert_batch xs =
    let n = Array.length xs in
    if n = 0 then Ok [||]
    else if Array.exists is_zero xs then Error `Zero_scalar
    else begin
      let prefix = Array.make n one in
      let acc = ref one in
      for i = 0 to n - 1 do
        prefix.(i) <- !acc;
        acc := mul !acc xs.(i)
      done;
      match invert !acc with
      | Error _ as e -> e
      | Ok inv_all ->
          let out = Array.make n one in
          let running = ref inv_all in
          for i = n - 1 downto 0 do
            out.(i) <- mul !running prefix.(i);
            running := mul !running xs.(i)
          done;
          Ok out
    end

  module Acc = struct
    (* A 32-byte mutable buffer. Operands are handed to the C stub through
       [Bytes.unsafe_to_string], which is sound here and is the whole point: the stub
       only reads its inputs, and copying them would materialise exactly the secret
       this type exists to avoid materialising. *)
    type acc = Bytes.t

    let create () = Bytes.make 32 '\000'
    let set (d : acc) (s : t) = Bytes.blit_string s 0 d 0 32

    let of_scalar s =
      let d = create () in
      set d s;
      d

    let reveal (d : acc) = Bytes.to_string d

    let muladd ~dst ~a ~b ~c =
      P.scalar_muladd_into dst (Bytes.unsafe_to_string a)
        (Bytes.unsafe_to_string b) (Bytes.unsafe_to_string c)

    (* dst <- dst*1 + x. sc_muladd loads all its operands before storing, so dst
       aliasing an input is safe. *)
    let one_acc = of_scalar one32

    let add ~dst x =
      P.scalar_muladd_into dst
        (Bytes.unsafe_to_string dst)
        (Bytes.unsafe_to_string one_acc)
        (Bytes.unsafe_to_string x)

    let wipe (d : acc) = Bytes.fill (Sys.opaque_identity d) 0 32 '\000'
    let wiped (d : acc) = Eqaf.equal (Bytes.unsafe_to_string d) zero32
  end

  let random rand =
    match Mpc.Rand.bytes rand 64 with
    | Error _ as e -> e
    | Ok wide ->
        let s = P.scalar_reduce wide in
        if is_zero s then
          Error `Rng_failure (* probability ~2^-252; not worth a retry loop *)
        else Ok s
end

module Element = struct
  type scalar = Scalar.t

  type t =
    string (* 32-byte RFC 8032 encoding of a prime-order-subgroup point *)

  let identity = one32
  let is_identity p = Eqaf.equal p identity
  let equal = Eqaf.equal
  let serialize t = t

  (* mirage-crypto's Ed25519 stubs read exactly 32 bytes from each argument without
     checking, so a short string would be a heap over-read. Every value of this type is
     produced by [deserialize] or by another operation here, so the invariant already
     holds; the check costs nothing beside a scalar multiplication and keeps a future
     change from turning a length bug into an out-of-bounds read. *)
  let check32 what s =
    if String.length s <> 32 then
      invalid_arg
        (Printf.sprintf "Mpc_ed25519.Element.%s: expected a 32-byte point" what)

  let add a b =
    check32 "add" a;
    check32 "add" b;
    match P.point_add a b with
    | Ok r -> r
    | Error _ ->
        (* Unreachable: [t] is only ever produced by this module, and every constructor
         either validates the encoding or derives it from valid points. *)
        invalid_arg
          "Mpc_ed25519.Element.add: invariant violated, invalid point encoding"

  let neg p =
    if is_identity p then p
    else
      (* -(x, y) = (-x, y); the encoding carries the sign of x in bit 7 of byte 31.
         The identity is the only prime-order point with x = 0, and it is excluded
         above, so this never produces the non-canonical "negative zero" encoding. *)
      String.mapi
        (fun i c -> if i = 31 then Char.chr (Char.code c lxor 0x80) else c)
        p

  let sub a b = add a (neg b)
  let scalar_mul_base s = P.scalar_mult_base s

  (* verify_double_base ~k ~pub ~s is s*B - k*P. With s = 0 and k = -n this is n*P.
     VARIABLE TIME in [n]: public scalars only. See the allowlist in CONTRIBUTING.md. *)
  let scalar_mul n p =
    check32 "scalar_mul" p;
    let _ok, r = P.verify_double_base ~k:(Scalar.neg n) ~pub:p ~s:zero32 in
    r

  let generator = scalar_mul_base one32

  let deserialize s =
    if String.length s <> 32 then Error `Invalid_length
    else begin
      (* mirage-crypto's fe_frombytes masks bit 255 and does not check y < p, so a
         non-canonical encoding would be silently accepted. Check it here. *)
      let y =
        String.mapi
          (fun i c -> if i = 31 then Char.chr (Char.code c land 0x7f) else c)
          s
      in
      if not (lt_le y p_le) then Error `Invalid_format
      else if not (P.point_valid s) then Error `Not_on_curve
      else if is_identity s then Error `At_infinity
      else
        (* Prime-order-subgroup check: L*P must be the identity. verify_double_base
           computes 0*B - L*P = -(L*P), and the identity is its own negation. The
           underlying slide() scans all 256 scalar bits without reduction, so passing
           L itself is meaningful. *)
        let _ok, lp = P.verify_double_base ~k:l_le ~pub:s ~s:zero32 in
        if not (is_identity lp) then Error `Low_order else Ok s
    end
end

module Suite = struct
  let id = context_string
  let ns = 32
  let ne = 32
  let nh = 64
  let suite_tag = 0x01

  module Scalar = Scalar
  module Element = Element

  let reduce s = P.scalar_reduce (sha512 s)
  let h1 m = reduce (context_string ^ "rho" ^ m)

  (* No context string, deliberately: this makes the challenge exactly
     SHA512(R || A || M), the RFC 8032 challenge, which is what makes an aggregated
     FROST signature verifiable by a stock Ed25519 verifier. It looks like a bug. *)
  let h2 m = reduce m
  let h3 m = reduce (context_string ^ "nonce" ^ m)
  let h4 m = sha512 (context_string ^ "msg" ^ m)
  let h5 m = sha512 (context_string ^ "com" ^ m)

  (* RFC 9591 does not specify a DKG proof-of-knowledge challenge hash and publishes
     no vectors for it. See CONTRIBUTING.md for the interop consequences. *)
  let hdkg m = reduce (context_string ^ "dkg" ^ m)
end
