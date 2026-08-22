type t = { buf : Bytes.t; mutable live : bool }

let of_bytes b = { buf = b; live = true }
let of_string s = of_bytes (Bytes.of_string s)
let length t = Bytes.length t.buf
let wiped t = not t.live
let get t = if t.live then Some (Bytes.to_string t.buf) else None
let with_bytes t f = if t.live then Some (f t.buf) else None

let wipe t =
  if t.live then begin
    Bytes.fill (Sys.opaque_identity t.buf) 0 (Bytes.length t.buf) '\000';
    t.live <- false
  end

let wipe_all = List.iter wipe

let equal a b =
  match (a.live, b.live) with
  | false, false -> true
  | false, true | true, false -> false
  | true, true ->
      Bytes.length a.buf = Bytes.length b.buf
      && Eqaf.equal
           (Bytes.unsafe_to_string a.buf)
           (Bytes.unsafe_to_string b.buf)
