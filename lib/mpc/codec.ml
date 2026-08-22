type error =
  [ `Eof of int
  | `Trailing of int
  | `Invalid_length
  | `Invalid_format
  | `Msg of string ]

let error_to_string : [< error ] -> string = function
  | `Eof n -> Printf.sprintf "unexpected end of input: wanted %d more byte(s)" n
  | `Trailing n -> Printf.sprintf "%d trailing byte(s) after a complete parse" n
  | `Invalid_length -> "invalid length"
  | `Invalid_format -> "invalid format"
  | `Msg m -> m

let pp_error ppf e = Format.pp_print_string ppf (error_to_string e)

module W = struct
  type t = Buffer.t

  let create ?(size = 256) () = Buffer.create size
  let contents = Buffer.contents
  let length = Buffer.length
  let byte = Buffer.add_char
  let bytes = Buffer.add_string

  let fixed w ~len s =
    if String.length s <> len then
      invalid_arg
        (Printf.sprintf "Mpc.Codec.W.fixed: expected %d bytes, got %d" len
           (String.length s));
    Buffer.add_string w s

  let u8 w n =
    if n < 0 || n > 0xff then invalid_arg "Mpc.Codec.W.u8: out of range";
    Buffer.add_char w (Char.unsafe_chr n)

  let u16 w n =
    if n < 0 || n > 0xffff then invalid_arg "Mpc.Codec.W.u16: out of range";
    Buffer.add_char w (Char.unsafe_chr ((n lsr 8) land 0xff));
    Buffer.add_char w (Char.unsafe_chr (n land 0xff))

  let u32 w n =
    let b i =
      Char.unsafe_chr
        (Int32.to_int (Int32.logand (Int32.shift_right_logical n i) 0xffl))
    in
    Buffer.add_char w (b 24);
    Buffer.add_char w (b 16);
    Buffer.add_char w (b 8);
    Buffer.add_char w (b 0)

  let str16 w s =
    let n = String.length s in
    if n > 0xffff then invalid_arg "Mpc.Codec.W.str16: string too long";
    u16 w n;
    Buffer.add_string w s

  let str32 w s =
    u32 w (Int32.of_int (String.length s));
    Buffer.add_string w s

  let vector16 w f xs =
    let n = List.length xs in
    if n > 0xffff then invalid_arg "Mpc.Codec.W.vector16: too many elements";
    u16 w n;
    List.iter (f w) xs

  let to_string f x =
    let w = create () in
    f w x;
    contents w
end

module R = struct
  type t = { src : string; mutable pos : int; stop : int }

  exception Parse_error of error

  let fail e = raise (Parse_error (e :> error))
  let pos r = r.pos
  let remaining r = r.stop - r.pos
  let eof r = r.pos >= r.stop

  let need r n =
    if n < 0 then fail `Invalid_length;
    let rem = remaining r in
    if rem < n then fail (`Eof (n - rem))

  let take r n =
    need r n;
    let s = String.sub r.src r.pos n in
    r.pos <- r.pos + n;
    s

  let fixed = take

  let byte r =
    need r 1;
    let c = String.unsafe_get r.src r.pos in
    r.pos <- r.pos + 1;
    c

  let u8 r = Char.code (byte r)

  (* Check the full width up front rather than byte by byte, so the reported
     [`Eof n] is the true deficit and not whatever happened to remain when the
     first short read occurred. *)
  let u16 r =
    need r 2;
    let hi = u8 r in
    let lo = u8 r in
    (hi lsl 8) lor lo

  let u32 r =
    need r 4;
    let b () = Int32.of_int (u8 r) in
    let a = b () in
    let c = b () in
    let d = b () in
    let e = b () in
    Int32.logor (Int32.shift_left a 24)
      (Int32.logor (Int32.shift_left c 16)
         (Int32.logor (Int32.shift_left d 8) e))

  let str16 r =
    let n = u16 r in
    take r n

  let str32 r =
    let n32 = u32 r in
    (* A length that does not fit in [int], or exceeds what is left, cannot be honest.
       Check before allocating. *)
    if Int32.compare n32 0l < 0 then fail `Invalid_length;
    let n = Int32.to_int n32 in
    if n > remaining r then fail (`Eof (n - remaining r));
    take r n

  let count16 r =
    let n = u16 r in
    (* Every element occupies at least one byte. *)
    if n > remaining r then fail (`Eof (n - remaining r));
    n

  let vector16 r f =
    let n = count16 r in
    List.init n (fun _ -> f r)

  let sub r n =
    need r n;
    let s = { src = r.src; pos = r.pos; stop = r.pos + n } in
    r.pos <- r.pos + n;
    s

  let run ?(exact = true) f s =
    let r = { src = s; pos = 0; stop = String.length s } in
    match f r with
    | v ->
        if exact && not (eof r) then Error (`Trailing (remaining r)) else Ok v
    | exception Parse_error e -> Error e
end
