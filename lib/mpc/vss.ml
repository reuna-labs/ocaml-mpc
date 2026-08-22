module Make (C : Group.CIPHERSUITE) = struct
  module S = Shamir.Make (C)
  module El = C.Element
  module Sc = C.Scalar

  type t = El.t array

  let commit p = Array.map El.scalar_mul_base (S.coefficients p)
  let secret_commitment c = c.(0)
  let threshold c = Array.length c

  (* sum_k id^k * phi_k, by Horner in the exponent: acc <- id * acc + phi_k.
     [id] is a public participant identifier; scalar_mul is allowlisted here. *)
  let eval_commitment c id =
    let n = Array.length c in
    let acc = ref c.(n - 1) in
    for k = n - 2 downto 0 do
      acc := El.add (El.scalar_mul id !acc) c.(k)
    done;
    !acc

  let verify_share c (sh : S.share) =
    if Array.length c = 0 then Error `Bad_share
    else if El.equal (El.scalar_mul_base sh.value) (eval_commitment c sh.id)
    then Ok ()
    else Error `Bad_share

  let combine = function
    | [] -> Error `Bad_threshold
    | first :: _ as cs ->
        let t = Array.length first in
        if t = 0 then Error `Bad_threshold
        else if List.exists (fun c -> Array.length c <> t) cs then
          Error `Length_mismatch
        else
          Ok
            (Array.init t (fun k ->
                 List.fold_left (fun acc c -> El.add acc c.(k)) El.identity cs))

  let participant_public_key cs ~id =
    match combine cs with
    | Error e -> Error e
    | Ok c -> Ok (eval_commitment c id)

  let serialize c =
    let w = Codec.W.create () in
    Array.iter (fun p -> Codec.W.fixed w ~len:C.ne (El.serialize p)) c;
    Codec.W.contents w

  let deserialize ~threshold s =
    if threshold < 1 then Error `Bad_threshold
    else if String.length s <> threshold * C.ne then Error `Invalid_length
    else begin
      let out = Array.make threshold El.identity in
      let rec go k =
        if k = threshold then Ok out
        else
          match El.deserialize (String.sub s (k * C.ne) C.ne) with
          | Error e -> Error (e :> Error.t)
          | Ok p ->
              out.(k) <- p;
              go (k + 1)
      in
      go 0
    end
end
