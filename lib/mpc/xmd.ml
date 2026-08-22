let expand_message_xmd ~hash ~block_size ~digest_size ~dst ~msg ~len =
  if len <= 0 || len > 255 * digest_size then Error `Invalid_length
  else begin
    (* RFC 9380 5.3.3: a DST longer than 255 bytes is hashed down first. The length is
       encoded in one byte below, so an unhashed long DST would make the encoding
       ambiguous. *)
    let dst =
      if String.length dst > 255 then hash ("H2C-OVERSIZE-DST-" ^ dst) else dst
    in
    let dst_prime = dst ^ String.make 1 (Char.chr (String.length dst)) in
    let z_pad = String.make block_size '\000' in
    let l_i_b_str =
      String.init 2 (fun i ->
          Char.chr ((len lsr if i = 0 then 8 else 0) land 0xff))
    in
    let b_0 =
      hash (String.concat "" [ z_pad; msg; l_i_b_str; "\000"; dst_prime ])
    in
    let b_1 = hash (String.concat "" [ b_0; "\001"; dst_prime ]) in
    let buf = Buffer.create len in
    Buffer.add_string buf b_1;
    let prev = ref b_1 in
    let i = ref 2 in
    while Buffer.length buf < len do
      (* b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime) *)
      let x =
        String.init digest_size (fun k ->
            Char.chr (Char.code b_0.[k] lxor Char.code !prev.[k]))
      in
      let b_i =
        hash (String.concat "" [ x; String.make 1 (Char.chr !i); dst_prime ])
      in
      Buffer.add_string buf b_i;
      prev := b_i;
      incr i
    done;
    Ok (String.sub (Buffer.contents buf) 0 len)
  end
