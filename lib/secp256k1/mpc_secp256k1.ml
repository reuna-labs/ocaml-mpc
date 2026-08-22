(* FROST(secp256k1, SHA-256), RFC 9591 Section 6.5.

   Scalars are 32-byte big-endian values mod n; elements are 33-byte compressed SEC1
   encodings. Read the audit table in the .mli before changing anything here. *)

module P = Mirage_crypto_ec.P256k1.Primitive

let of_hex h =
  String.init
    (String.length h / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

(* Group order n, big-endian. *)
let n_be =
  of_hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

let scalar_bytes = 32
let element_bytes = 33
let zero32 = String.make scalar_bytes '\000'

(* The identity has no SEC1 encoding, and the primitive layer renders it as a single
   0x00 byte. The group signature requires a fixed width, so it is encoded here as
   [element_bytes] zeroes -- a string [deserialize] rejects, which is what RFC 9591
   requires of DeserializeElement anyway. *)
let identity_octets = String.make element_bytes '\000'

(* Branch-free "is [s] strictly less than the 32-byte big-endian [m]?": subtract with
   borrow from the least significant end and report the final borrow. For OCaml's
   63-bit int and d in [-256, 255], (d lsr 62) land 1 is 1 exactly when d < 0. *)
let lt_be s m =
  let borrow = ref 0 in
  for i = scalar_bytes - 1 downto 0 do
    let d =
      Char.code (String.unsafe_get s i)
      - Char.code (String.unsafe_get m i)
      - !borrow
    in
    borrow := (d lsr 62) land 1
  done;
  !borrow = 1

let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))
let context_string = "FROST-secp256k1-SHA256-v1"

module Scalar = struct
  type t = string (* 32 bytes, big-endian, reduced mod n *)

  let zero = zero32
  let one = P.scalar_one
  let add = P.scalar_add
  let mul = P.scalar_mul
  let neg = P.scalar_negate
  let sub a b = add a (neg b)
  let muladd a b c = add (mul a b) c
  let equal = Eqaf.equal
  let is_zero a = Eqaf.equal a zero
  let serialize t = t

  let deserialize s =
    if String.length s <> scalar_bytes then Error `Invalid_length
    else if not (lt_be s n_be) then Error `Invalid_range
    else Ok s

  (* The primitive defines inv 0 = 0; the group signature requires an error, and the
     branch is on a constant-time comparison of a value the caller already holds. *)
  let invert a = if is_zero a then Error `Zero_scalar else Ok (P.scalar_inv a)

  let invert_batch xs =
    let m = Array.length xs in
    if m = 0 then Ok [||]
    else if Array.exists is_zero xs then Error `Zero_scalar
    else begin
      let prefix = Array.make m one in
      let acc = ref one in
      for i = 0 to m - 1 do
        prefix.(i) <- !acc;
        acc := mul !acc xs.(i)
      done;
      match invert !acc with
      | Error _ as e -> e
      | Ok inv_all ->
          let out = Array.make m one in
          let running = ref inv_all in
          for i = m - 1 downto 0 do
            out.(i) <- mul !running prefix.(i);
            running := mul !running xs.(i)
          done;
          Ok out
    end

  (* Big-endian, so compare from the most significant byte down. Public data only. *)
  let compare a b =
    let rec go i =
      if i >= scalar_bytes then 0
      else
        let d = Char.code a.[i] - Char.code b.[i] in
        if d <> 0 then d else go (i + 1)
    in
    go 0

  let of_int k =
    if k < 1 || k > 0xffff then Error `Invalid_range
    else
      Ok
        (String.init scalar_bytes (fun i ->
             if i = scalar_bytes - 1 then Char.chr (k land 0xff)
             else if i = scalar_bytes - 2 then Char.chr ((k lsr 8) land 0xff)
             else '\000'))

  (* RFC 9380 hash_to_field for the scalar field: OS2IP of 48 uniform bytes, mod n.

     n sits just below 2^256, so reducing a 256-bit hash would be measurably biased --
     which is why this ciphersuite specifies hash_to_field where Ed25519 gets away with
     a wide reduce. The reduction is done as x = hi * 2^192 + lo over 24-byte halves:
     both halves are below 2^192 < n and therefore already canonical, 2^192 is itself
     canonical, and the whole thing is one multiply and one add in the constant-time
     scalar field. No bignum, and no arithmetic written here. *)
  let two_192 =
    String.init scalar_bytes (fun i -> if i = 7 then '\001' else '\000')

  let of_uniform_bytes s =
    if String.length s <> 48 then Error `Invalid_length
    else begin
      let pad24 sub =
        String.init scalar_bytes (fun i ->
            if i < 8 then '\000' else sub.[i - 8])
      in
      let hi = pad24 (String.sub s 0 24) and lo = pad24 (String.sub s 24 24) in
      Ok (add (mul hi two_192) lo)
    end

  let random rand =
    match Mpc.Rand.bytes rand 48 with
    | Error _ as e -> e
    | Ok wide -> (
        match of_uniform_bytes wide with
        | Error _ -> Error `Rng_failure
        | Ok s -> if is_zero s then Error `Rng_failure else Ok s)

  module Acc = struct
    (* A 32-byte mutable buffer. Operands reach the C through Bytes.unsafe_to_string:
       sound because the primitives only read them, and the point of the type -- copying
       an operand would materialise exactly the secret this exists to keep in a buffer
       that can be overwritten. *)
    type acc = Bytes.t

    let create () = Bytes.make scalar_bytes '\000'
    let set (d : acc) (s : t) = Bytes.blit_string s 0 d 0 scalar_bytes

    let of_scalar s =
      let d = create () in
      set d s;
      d

    let reveal (d : acc) = Bytes.to_string d

    let muladd ~dst ~a ~b ~c =
      (* No fused muladd in this primitive layer, so multiply into a scratch buffer
         first: writing the product straight into dst would clobber an operand that
         aliases it. *)
      let t = create () in
      P.scalar_mul_into t (Bytes.unsafe_to_string a) (Bytes.unsafe_to_string b);
      P.scalar_add_into dst (Bytes.unsafe_to_string t)
        (Bytes.unsafe_to_string c);
      Bytes.fill (Sys.opaque_identity t) 0 scalar_bytes '\000'

    let add ~dst x =
      P.scalar_add_into dst
        (Bytes.unsafe_to_string dst)
        (Bytes.unsafe_to_string x)

    let wipe (d : acc) =
      Bytes.fill (Sys.opaque_identity d) 0 scalar_bytes '\000'

    let wiped (d : acc) = Eqaf.equal (Bytes.unsafe_to_string d) zero32
  end
end

module Element = struct
  type scalar = Scalar.t

  (* Carried in its encoded form so that [serialize] is total and fixed width, and so
     that equality is a byte comparison rather than a coordinate one. *)
  type t = string

  let identity = identity_octets
  let is_identity p = Eqaf.equal p identity
  let equal = Eqaf.equal
  let serialize t = t

  let decode what p =
    match P.point_of_octets p with
    | Ok q -> q
    | Error _ ->
        invalid_arg
          (Printf.sprintf "Mpc_secp256k1.Element.%s: invariant violated" what)

  let encode q = if P.point_is_infinity q then identity else P.point_to_octets q

  let add a b =
    if is_identity a then b
    else if is_identity b then a
    else encode (P.point_add (decode "add" a) (decode "add" b))

  let neg p =
    if is_identity p then p
    else
      (* Negating a compressed SEC1 point flips the parity byte between 0x02 and 0x03:
         the two encodings differ only in the sign of y. *)
      String.mapi
        (fun i c -> if i = 0 then Char.chr (Char.code c lxor 1) else c)
        p

  let sub a b = add a (neg b)

  let scalar_mul_base s =
    if Scalar.is_zero s then identity else encode (P.scalar_mult_base s)

  let scalar_mul k p =
    (* The primitive requires k in [1, n-1]; zero is the one value it will not take, and
       k * p is the identity there. *)
    if Scalar.is_zero k || is_identity p then identity
    else encode (P.scalar_mult k (decode "scalar_mul" p))

  let generator = scalar_mul_base Scalar.one

  let deserialize s =
    if String.length s <> element_bytes then Error `Invalid_length
    else if is_identity s then Error `At_infinity
    else
      match P.point_of_octets s with
      | Ok q ->
          if P.point_is_infinity q then Error `At_infinity
          else Ok (P.point_to_octets q)
      | Error `Invalid_format -> Error `Invalid_format
      | Error `Invalid_length -> Error `Invalid_length
      | Error _ -> Error `Not_on_curve
end

module Suite = struct
  let id = context_string
  let ns = scalar_bytes
  let ne = element_bytes
  let nh = 32
  let suite_tag = 0x02

  module Scalar = Scalar
  module Element = Element

  (* RFC 9591 6.5: H1, H2 and H3 are hash_to_field(m, 1) over expand_message_xmd with
     SHA-256; H4 and H5 are the plain hash. L = 48, from ceil((256 + 128) / 8). *)
  let h2f ~dst m =
    match
      Mpc.Xmd.expand_message_xmd ~hash:sha256 ~block_size:64 ~digest_size:32
        ~dst ~msg:m ~len:48
    with
    | Error _ ->
        invalid_arg "Mpc_secp256k1: expand_message_xmd rejected a valid length"
    | Ok wide -> (
        match Scalar.of_uniform_bytes wide with
        | Ok s -> s
        | Error _ ->
            invalid_arg "Mpc_secp256k1: hash_to_field produced the wrong width")

  let h1 m = h2f ~dst:(context_string ^ "rho") m
  let h2 m = h2f ~dst:(context_string ^ "chal") m
  let h3 m = h2f ~dst:(context_string ^ "nonce") m
  let h4 m = sha256 (context_string ^ "msg" ^ m)
  let h5 m = sha256 (context_string ^ "com" ^ m)

  (* RFC 9591 does not specify this; it matches ZcashFoundation/frost. See
     lib/frost/keygen.ml and test/interop/README.md. *)
  let hdkg m = h2f ~dst:(context_string ^ "dkg") m
end
