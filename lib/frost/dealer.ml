module Make (C : Mpc.Group.CIPHERSUITE) = struct
  module V = Mpc.Vss.Make (C)
  module Sh = V.S
  module El = C.Element

  type key_package = {
    id : C.Scalar.t;
    share : C.Scalar.t;
    verification_share : El.t;
    group_public_key : El.t;
    threshold : int;
  }

  type public_key_package = {
    pk : El.t;
    commitment : V.t;
    verification_shares : (C.Scalar.t * El.t) list;
  }

  let finish poly ~ids ~threshold =
    match Sh.shares_of_poly poly ~ids with
    | Error e ->
        Sh.wipe poly;
        Error e
    | Ok shares ->
        let commitment = V.commit poly in
        Sh.wipe poly;
        let pk = V.secret_commitment commitment in
        let verification_shares =
          List.map
            (fun (s : Sh.share) -> (s.Sh.id, El.scalar_mul_base s.Sh.value))
            shares
        in
        let packages =
          List.map2
            (fun (s : Sh.share) (_, vs) ->
              {
                id = s.Sh.id;
                share = s.Sh.value;
                verification_share = vs;
                group_public_key = pk;
                threshold;
              })
            shares verification_shares
        in
        Ok (packages, { pk; commitment; verification_shares })

  let generate rand ~secret ~threshold ~ids =
    let n = List.length ids in
    if threshold < 1 || threshold > n then Error `Bad_threshold
    else
      match Sh.random rand ~degree:(threshold - 1) ~secret with
      | Error e -> Error e
      | Ok poly -> finish poly ~ids ~threshold

  let of_coefficients ~coefficients ~ids =
    let threshold = Array.length coefficients in
    if threshold < 1 || threshold > List.length ids then Error `Bad_threshold
    else
      match Sh.of_coefficients coefficients with
      | Error e -> Error e
      | Ok poly -> finish poly ~ids ~threshold
end
