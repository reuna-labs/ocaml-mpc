module Make (C : Mpc.Group.CIPHERSUITE) = struct
  module Sc = C.Scalar
  module El = C.Element

  type commitment = { hiding : El.t; binding : El.t }
  type commitment_list = (Sc.t * commitment) list

  let commitment_list l =
    if List.exists (fun (id, _) -> Sc.is_zero id) l then Error `Zero_id
    else begin
      let sorted = List.stable_sort (fun (a, _) (b, _) -> Sc.compare a b) l in
      let rec dup = function
        | (a, _) :: ((b, _) :: _ as tl) -> if Sc.equal a b then true else dup tl
        | _ -> false
      in
      if dup sorted then Error `Duplicate_id else Ok sorted
    end

  let participants (l : commitment_list) = List.map fst l
  let encode_identifier = Sc.serialize

  let encode_commitment_list l =
    let b = Buffer.create (List.length l * ((2 * C.ne) + C.ns)) in
    List.iter
      (fun (id, c) ->
        Buffer.add_string b (encode_identifier id);
        Buffer.add_string b (El.serialize c.hiding);
        Buffer.add_string b (El.serialize c.binding))
      l;
    Buffer.contents b

  let binding_factor_input ~group_public_key ~commitment_list ~msg id =
    String.concat ""
      [
        El.serialize group_public_key;
        C.h4 msg;
        C.h5 (encode_commitment_list commitment_list);
        encode_identifier id;
      ]

  let challenge_input ~group_commitment ~group_public_key ~msg =
    El.serialize group_commitment ^ El.serialize group_public_key ^ msg

  let signature ~r ~z = El.serialize r ^ Sc.serialize z

  let parse_signature s =
    if String.length s <> C.ne + C.ns then Error `Invalid_length
    else
      match El.deserialize (String.sub s 0 C.ne) with
      | Error e -> Error (e :> [> `Invalid_length | Mpc.Error.t ])
      | Ok r -> (
          match Sc.deserialize (String.sub s C.ne C.ns) with
          | Error e -> Error (e :> [> `Invalid_length | Mpc.Error.t ])
          | Ok z -> Ok (r, z))
end
