type t = int -> string

let v f = f

let bytes t n =
  if n < 0 then Error `Rng_failure
  else
    match t n with
    | s when String.length s = n -> Ok s
    | _ -> Error `Rng_failure
    | exception _ -> Error `Rng_failure

let bytes_exn t n =
  match bytes t n with
  | Ok s -> s
  | Error `Rng_failure ->
      failwith "Mpc.Rand: randomness source returned the wrong length"
