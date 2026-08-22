module Make (C : Mpc.Group.CIPHERSUITE) = struct
  module E = Encoding.Make (C)
  module Sh = Mpc.Shamir.Make (C)
  module Sc = C.Scalar
  module El = C.Element

  type nonces = { hiding : Sc.t; binding : Sc.t }

  let nonce_generate rand ~secret =
    match Mpc.Rand.bytes rand 32 with
    | Error _ -> Error `Rng_failure
    | Ok r -> Ok (C.h3 (r ^ Sc.serialize secret))

  let commit rand ~secret =
    match nonce_generate rand ~secret with
    | Error e -> Error e
    | Ok hiding -> (
        match nonce_generate rand ~secret with
        | Error e -> Error e
        | Ok binding ->
            Ok
              ( { hiding; binding },
                {
                  E.hiding = El.scalar_mul_base hiding;
                  E.binding = El.scalar_mul_base binding;
                } ))

  let binding_factors ~group_public_key ~commitment_list ~msg =
    List.map
      (fun (id, _) ->
        ( id,
          C.h1
            (E.binding_factor_input ~group_public_key ~commitment_list ~msg id)
        ))
      commitment_list

  let group_commitment ~commitment_list ~binding_factors =
    List.fold_left2
      (fun acc (_, (c : E.commitment)) (_, rho) ->
        (* rho is a public binding factor: scalar_mul is allowlisted here. *)
        El.add acc (El.add c.E.hiding (El.scalar_mul rho c.E.binding)))
      El.identity commitment_list binding_factors

  let challenge ~group_commitment ~group_public_key ~msg =
    C.h2 (E.challenge_input ~group_commitment ~group_public_key ~msg)

  let lookup id l =
    match List.find_opt (fun (i, _) -> Sc.equal i id) l with
    | Some (_, v) -> Ok v
    | None -> Error `Not_a_participant

  let sign ~id ~share ~group_public_key ~nonces ~msg ~commitment_list =
    let bf = binding_factors ~group_public_key ~commitment_list ~msg in
    match lookup id bf with
    | Error e -> Error e
    | Ok rho -> (
        let r = group_commitment ~commitment_list ~binding_factors:bf in
        let c = challenge ~group_commitment:r ~group_public_key ~msg in
        match Sh.lagrange ~ids:(E.participants commitment_list) ~id with
        | Error e -> Error e
        | Ok lambda ->
            (* z = d + e*rho + lambda*s*c.

               Computed in wipeable accumulators and erased before returning: d, e and
               s are secret, and so is every partial value. Only z escapes, and z is
               public -- it is the signature share, about to be sent. *)
            let acc = Sc.Acc.create () in
            let hiding = Sc.Acc.of_scalar nonces.hiding in
            let binding = Sc.Acc.of_scalar nonces.binding in
            let ksec = Sc.Acc.of_scalar share in
            let term = Sc.Acc.create () in
            let zero = Sc.Acc.create () in
            (* acc <- e*rho + d *)
            Sc.Acc.muladd ~dst:acc ~a:binding ~b:(Sc.Acc.of_scalar rho)
              ~c:hiding;
            (* term <- lambda*s ; acc <- term*c + acc *)
            Sc.Acc.muladd ~dst:term ~a:(Sc.Acc.of_scalar lambda) ~b:ksec ~c:zero;
            Sc.Acc.muladd ~dst:acc ~a:term ~b:(Sc.Acc.of_scalar c) ~c:acc;
            let z = Sc.Acc.reveal acc in
            List.iter Sc.Acc.wipe [ acc; hiding; binding; ksec; term ];
            Ok z)

  let aggregate ~group_commitment:r shares =
    E.signature ~r ~z:(List.fold_left Sc.add Sc.zero shares)

  let verify_signature_share ~id ~verification_share ~sig_share ~commitment_list
      ~binding_factors:bf ~group_public_key ~msg =
    match lookup id bf with
    | Error e -> Error e
    | Ok rho -> (
        match lookup id commitment_list with
        | Error e -> Error e
        | Ok (c : E.commitment) -> (
            match Sh.lagrange ~ids:(E.participants commitment_list) ~id with
            | Error e -> Error e
            | Ok lambda ->
                let r = group_commitment ~commitment_list ~binding_factors:bf in
                let chal =
                  challenge ~group_commitment:r ~group_public_key ~msg
                in
                (* All of rho, chal and lambda are public. *)
                let comm_share =
                  El.add c.E.hiding (El.scalar_mul rho c.E.binding)
                in
                let lhs = El.scalar_mul_base sig_share in
                let rhs =
                  El.add comm_share
                    (El.scalar_mul (Sc.mul chal lambda) verification_share)
                in
                if El.equal lhs rhs then Ok () else Error `Bad_share))

  let verify ~group_public_key ~msg s =
    match E.parse_signature s with
    | Error _ -> false
    | Ok (r, z) ->
        let c = challenge ~group_commitment:r ~group_public_key ~msg in
        El.equal (El.scalar_mul_base z)
          (El.add r (El.scalar_mul c group_public_key))
end
