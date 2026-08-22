let default_max_frame = 1024 * 1024
let header_length = 4

let check_max = function
  | m when m < 1 -> invalid_arg "Mpc_lwt.Framing: max_frame must be positive"
  | m -> m

let encode ?(max_frame = default_max_frame) payload =
  let max_frame = check_max max_frame in
  let len = Cstruct.length payload in
  if len > max_frame then
    invalid_arg
      (Printf.sprintf
         "Mpc_lwt.Framing.encode: payload of %d bytes exceeds max_frame %d" len
         max_frame);
  let out = Cstruct.create (header_length + len) in
  Cstruct.BE.set_uint32 out 0 (Int32.of_int len);
  Cstruct.blit payload 0 out header_length len;
  out

let encode_string ?max_frame s = encode ?max_frame (Cstruct.of_string s)

(* [buffered] is a view over bytes handed to [feed]. Popping a frame only shifts the
   window and [next] returns a sub-view, so a read yielding whole frames copies nothing.
   The single copy is in [feed], and only when a frame straddles two reads. *)
type t = {
  max_frame : int;
  mutable buffered : Cstruct.t;
  mutable broken : bool;
}

let create ?(max_frame = default_max_frame) () =
  { max_frame = check_max max_frame; buffered = Cstruct.empty; broken = false }

let pending t = Cstruct.length t.buffered

let feed t chunk =
  if Cstruct.length chunk > 0 then
    t.buffered <-
      (if Cstruct.is_empty t.buffered then chunk
       else Cstruct.append t.buffered chunk)

let next t =
  if t.broken then `Error "framing: stream already desynchronised"
  else if Cstruct.length t.buffered < header_length then `Need_more
  else
    let len32 = Cstruct.BE.get_uint32 t.buffered 0 in
    (* Reject the declared length before buffering a single byte of the body. On a
       32-bit platform a length above max_int would also be nonsense. *)
    if Int32.compare len32 0l < 0 || Int32.to_int len32 > t.max_frame then begin
      t.broken <- true;
      `Error
        (Printf.sprintf
           "framing: declared frame length %ld exceeds max_frame %d" len32
           t.max_frame)
    end
    else
      let len = Int32.to_int len32 in
      if Cstruct.length t.buffered - header_length < len then `Need_more
      else begin
        let payload = Cstruct.sub t.buffered header_length len in
        t.buffered <- Cstruct.shift t.buffered (header_length + len);
        `Message payload
      end
